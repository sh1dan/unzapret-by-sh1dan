//! Regression tests for profile confusion, overly broad UDP grants and counters.
use local_dpi_bypass::{
    capture::{CaptureError, CapturedPacket, PacketCapture, ReceiveEvent},
    core::{
        config_loader::load_config, flow::FlowTable, pipeline::ActivePipelineEngine,
        segment::split_tcp_packet, InitialMetadata, PacketContext, PacketEngine, RunMode,
        Transport,
    },
    filtering::{
        list::{DomainEntry, IpEntry},
        DestinationFilter, FilterDecision, FilterEngine, TargetPreset,
    },
    strategies::{self, ProcessResult},
};
use std::{
    cell::RefCell, collections::VecDeque, path::Path, rc::Rc, sync::atomic::AtomicBool,
    time::Duration,
};

fn udp_context() -> PacketContext<'static> {
    PacketContext {
        packet: &[],
        destination: "203.0.113.10".parse().unwrap(),
        destination_port: 50001,
        transport: Transport::Udp,
        server_name: None,
        initial: InitialMetadata::Stun,
        initial_payload: true,
        filter: FilterDecision::Allow,
    }
}

fn preset() -> TargetPreset {
    TargetPreset {
        allow_domains: vec![],
        allow_ips: vec![],
        tcp_ports: vec![443],
        udp_ports: vec![50001],
    }
}

#[test]
fn runtime_tcp_profile_cannot_inject_udp_and_unknown_names_fail() {
    let strategy = strategies::create("split-tcp").unwrap();
    assert_eq!(strategy.name(), "split-tcp");
    assert_eq!(strategy.process(&udp_context()), ProcessResult::PassThrough);
    assert!(strategies::create("split-tcp-only").is_err());
    assert!(strategies::create("auto").is_err());
}

#[test]
fn stun_and_ports_do_not_override_allowlist() {
    let filter = FilterEngine::new(vec![], vec![], vec![preset()]);
    assert_eq!(filter.evaluate(&udp_context()), FilterDecision::NoMatch);
    let mut with_domains = preset();
    with_domains
        .allow_domains
        .push(DomainEntry::Suffix("discord.media".into()));
    let filter = FilterEngine::new(vec![], vec![], vec![with_domains]);
    assert_eq!(filter.evaluate(&udp_context()), FilterDecision::NoMatch);
}

#[test]
fn unknown_udp_domain_cannot_bypass_exclusions_even_with_ip_grant() {
    let mut allowed = preset();
    allowed
        .allow_ips
        .push(IpEntry::Single(udp_context().destination));
    let filter = FilterEngine::new(
        vec![],
        vec![DomainEntry::Exact("excluded.example".into())],
        vec![allowed],
    );
    assert_eq!(filter.evaluate(&udp_context()), FilterDecision::Unknown);
}

#[test]
fn disabled_capture_has_no_implicit_fallback_ports() {
    assert_eq!(
        FilterEngine::new(vec![], vec![], vec![]).build_windivert_filter(),
        "false"
    );
    let mut tcp_only = preset();
    tcp_only.udp_ports.clear();
    let filter = FilterEngine::new(vec![], vec![], vec![tcp_only]).build_windivert_filter();
    assert!(filter.contains("tcp.DstPort == 443"));
    assert!(!filter.contains("udp"));
}

#[test]
fn source_and_package_configs_select_tcp_only_runtime() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in [root.to_path_buf(), root.join("run")] {
        let loaded = load_config(&path).unwrap();
        assert_eq!(loaded.strategy, "split-tcp");
        assert!(!loaded.dry_run);
        assert!(loaded
            .filter_engine
            .presets
            .iter()
            .all(|p| p.udp_ports.is_empty()));
        assert!(!loaded
            .filter_engine
            .build_windivert_filter()
            .contains("udp"));
    }
}

fn tcp(flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 40 + payload.len()];
    let len = packet.len() as u16;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
    packet[16..20].copy_from_slice(&[203, 0, 113, 10]);
    packet[20..22].copy_from_slice(&55000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = flags;
    packet[40..].copy_from_slice(payload);
    packet
}

struct RecordingCapture {
    packets: VecDeque<Vec<u8>>,
    sent: Rc<RefCell<Vec<Vec<u8>>>>,
    mode: RunMode,
}
impl PacketCapture for RecordingCapture {
    type Address = ();
    fn mode(&self) -> RunMode {
        self.mode
    }
    fn receive(&mut self) -> Result<ReceiveEvent<()>, CaptureError> {
        Ok(match self.packets.pop_front() {
            Some(bytes) => ReceiveEvent::Packet(CapturedPacket { bytes, address: () }),
            None => ReceiveEvent::End,
        })
    }
    fn send(&mut self, packet: &CapturedPacket<()>) -> Result<(), CaptureError> {
        assert_eq!(self.mode, RunMode::Active, "dry-run may not send");
        self.sent.borrow_mut().push(packet.bytes.clone());
        Ok(())
    }
    fn shutdown_receive(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
    fn close(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
}

#[test]
fn empty_tcp_handshake_does_not_exhaust_one_packet_budget() {
    for mode in [RunMode::Active, RunMode::DryRun] {
        let sent = Rc::new(RefCell::new(Vec::new()));
        let mut allowed = preset();
        allowed
            .allow_ips
            .push(IpEntry::Single(udp_context().destination));
        let mut engine = ActivePipelineEngine::new(
            RecordingCapture {
                packets: VecDeque::from([tcp(2, &[]), tcp(16, &[]), tcp(24, b"payload")]),
                sent: sent.clone(),
                mode,
            },
            FilterEngine::new(vec![], vec![], vec![allowed]),
            FlowTable::new(8, Duration::from_secs(30), 1),
            strategies::create("split-tcp").unwrap(),
            |_| {},
        );
        let counters = engine.run(mode, &AtomicBool::new(true)).unwrap();
        assert_eq!(counters.eligible, 1);
        match mode {
            RunMode::Active => {
                assert_eq!(counters.modified, 1);
                assert_eq!(counters.would_modify, 0);
                assert_eq!(sent.borrow().len(), 4);
                let sent = sent.borrow();
                assert_eq!([&sent[2][40..], &sent[3][40..]].concat(), b"payload");
            }
            RunMode::DryRun => {
                assert_eq!(counters.modified, 0);
                assert_eq!(counters.would_modify, 1);
                assert!(sent.borrow().is_empty());
            }
        }
    }
}

#[test]
fn tcp_control_flags_with_payload_are_not_split() {
    for flags in [0x11, 0x12, 0x14, 0x30] {
        assert!(split_tcp_packet(&tcp(flags, b"payload"), 2).is_err());
    }
}
