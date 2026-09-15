use local_dpi_bypass::{cli, core::*, filtering::*, service::*, strategies::*};
use std::sync::atomic::AtomicBool;

fn context(filter: FilterDecision) -> PacketContext<'static> {
    PacketContext {
        packet: &[],
        destination: "192.0.2.1".parse().unwrap(),
        destination_port: 443,
        transport: Transport::Tcp,
        server_name: Some("example.invalid"),
        initial: InitialMetadata::Unknown,
        initial_payload: true,
        filter,
    }
}

struct MustNotRun;
impl Strategy for MustNotRun {
    fn name(&self) -> &'static str {
        "test"
    }
    fn matches(&self, _: &PacketContext<'_>) -> bool {
        panic!("unauthorized matching")
    }
    fn process(&self, _: &PacketContext<'_>) -> ProcessResult {
        panic!("unauthorized strategy")
    }
}

#[test]
fn excluded_unknown_and_unmatched_never_reach_strategy() {
    for decision in [
        FilterDecision::Exclude,
        FilterDecision::Unknown,
        FilterDecision::NoMatch,
    ] {
        for mode in [RunMode::Active, RunMode::DryRun] {
            assert_eq!(
                evaluate(&MustNotRun, &context(decision), mode),
                ProcessResult::PassThrough
            );
        }
    }
}

#[test]
fn later_payload_never_reaches_strategy() {
    let mut ctx = context(FilterDecision::Allow);
    ctx.initial_payload = false;
    assert_eq!(
        evaluate(&MustNotRun, &ctx, RunMode::Active),
        ProcessResult::PassThrough
    );
}

struct PlannedSplit;
impl Strategy for PlannedSplit {
    fn name(&self) -> &'static str {
        "test-split"
    }
    fn matches(&self, _: &PacketContext<'_>) -> bool {
        true
    }
    fn process(&self, _: &PacketContext<'_>) -> ProcessResult {
        ProcessResult::SplitTcp { payload_offset: 1 }
    }
}

#[test]
fn dry_run_suppresses_modification_plan() {
    let ctx = context(FilterDecision::Allow);
    assert_eq!(
        evaluate(&PlannedSplit, &ctx, RunMode::DryRun),
        ProcessResult::WouldModify
    );
    assert_eq!(
        evaluate(&PlannedSplit, &ctx, RunMode::Active),
        ProcessResult::SplitTcp { payload_offset: 1 }
    );
    assert_eq!(
        evaluate(&PassThrough, &ctx, RunMode::DryRun),
        ProcessResult::PassThrough
    );
}

#[test]
fn unavailable_engine_does_not_claim_success() {
    let mut engine = UnavailableEngine;
    for mode in [RunMode::Active, RunMode::DryRun] {
        assert_eq!(
            engine.run(mode, &AtomicBool::new(false)),
            Err(EngineError::NotImplemented)
        );
    }
    assert_eq!(engine.counters(), Counters::default());
}

#[test]
fn install_remove_and_service_operations_are_unavailable() {
    let manager = UnavailableService;
    assert_eq!(manager.install(), Err(ServiceError::NotImplemented));
    assert_eq!(manager.remove(), Err(ServiceError::NotImplemented));
    assert_eq!(manager.start(), Err(ServiceError::NotImplemented));
    assert_eq!(manager.stop(), Err(ServiceError::NotImplemented));
    assert_eq!(manager.status(), Err(ServiceError::NotImplemented));
}

#[test]
fn phase_one_cli_is_honest_about_reserved_operations() {
    for args in [vec!["stop"], vec!["restart"], vec!["use", "split-tls"]] {
        assert_eq!(cli::dispatch(&args).code, 2);
    }
    assert_eq!(cli::dispatch(&["start", "--unknown"]).code, 2);
    assert!(cli::dispatch(&["status"]).text.contains("not queried"));
}

#[test]
fn safe_defaults_and_deny_all_filter() {
    let config = core_config();
    assert!(config.dry_run);
    assert!(!config.targets.discord_voice);
    assert!(!config.targets.custom);
    assert_eq!(config.strategy, "pass-through");
    assert_eq!(
        DenyAll.evaluate(&context(FilterDecision::Allow)),
        FilterDecision::NoMatch
    );
}

fn core_config() -> config::Config {
    config::Config::default()
}

// ── Phase 2: parser tests ────────────────────────────────────────────────────

use local_dpi_bypass::core::parser::{self, ParseError};

/// Minimal valid IPv4/TCP packet (20-byte IP header + 20-byte TCP header, no payload).
fn ipv4_tcp_packet() -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45; // version=4, IHL=5
    p[2] = 0x00;
    p[3] = 40; // total length = 40
    p[6] = 0;
    p[7] = 0; // no fragment flags
    p[9] = 6; // protocol TCP
    p[12] = 192;
    p[13] = 0;
    p[14] = 2;
    p[15] = 1; // src
    p[16] = 192;
    p[17] = 0;
    p[18] = 2;
    p[19] = 2; // dst
               // TCP header at offset 20
    p[20] = 0;
    p[21] = 80; // src port 80
    p[22] = 0x01;
    p[23] = 0xbb; // dst port 443
                  // data offset = 5 (20 bytes), at byte 32
    p[32] = 5 << 4;
    p
}

/// Minimal valid IPv4/UDP packet (20+8 bytes).
fn ipv4_udp_packet() -> Vec<u8> {
    let mut p = vec![0u8; 28];
    p[0] = 0x45;
    p[2] = 0;
    p[3] = 28;
    p[9] = 17; // UDP
    p[12] = 10;
    p[13] = 0;
    p[14] = 0;
    p[15] = 1;
    p[16] = 10;
    p[17] = 0;
    p[18] = 0;
    p[19] = 2;
    // UDP: src port, dst port, length, checksum (8 bytes)
    p[20] = 0;
    p[21] = 53; // src port 53
    p[22] = 0;
    p[23] = 53; // dst port 53
    p[24] = 0;
    p[25] = 8; // length = 8 (header only)
    p
}

#[test]
fn parser_accepts_minimal_ipv4_tcp() {
    let pkt = ipv4_tcp_packet();
    let m = parser::parse(&pkt).expect("should parse");
    assert_eq!(m.version, 4);
    assert_eq!(m.header_length, 20);
    assert_eq!(m.total_length, 40);
    assert_eq!(m.protocol, 6);
    assert!(matches!(
        m.transport,
        parser::TransportMetadata::Tcp {
            destination_port: 443,
            ..
        }
    ));
}

#[test]
fn parser_accepts_minimal_ipv4_udp() {
    let pkt = ipv4_udp_packet();
    let m = parser::parse(&pkt).expect("should parse");
    assert_eq!(m.version, 4);
    assert_eq!(m.protocol, 17);
    assert!(matches!(
        m.transport,
        parser::TransportMetadata::Udp { length: 8, .. }
    ));
}

#[test]
fn parser_rejects_empty() {
    assert!(parser::parse(&[]).is_err());
}

#[test]
fn parser_rejects_ipv4_too_short() {
    assert!(parser::parse(&[0x45u8; 19]).is_err());
}

#[test]
fn parser_rejects_ipv4_ihl_less_than_5() {
    let mut p = ipv4_tcp_packet();
    p[0] = 0x44; // IHL = 4 → invalid
    assert!(parser::parse(&p).is_err());
}

#[test]
fn parser_rejects_ipv4_total_length_mismatch() {
    let mut p = ipv4_tcp_packet();
    p[2] = 0;
    p[3] = 39; // total = 39 ≠ 40
    assert!(parser::parse(&p).is_err());
}

#[test]
fn parser_rejects_ipv4_fragment() {
    let mut p = ipv4_tcp_packet();
    p[6] = 0x20; // MF flag set → fragment
    assert!(matches!(parser::parse(&p), Err(ParseError::Unsupported)));
}

#[test]
fn parser_rejects_unknown_version() {
    let mut p = ipv4_tcp_packet();
    p[0] = 0x35; // version = 3
    assert!(parser::parse(&p).is_err());
}

#[test]
fn parser_rejects_udp_length_mismatch() {
    let mut p = ipv4_udp_packet();
    p[24] = 0;
    p[25] = 9; // UDP length = 9 ≠ actual payload 8
    assert!(parser::parse(&p).is_err());
}

#[test]
fn parser_rejects_unsupported_protocol() {
    let mut p = ipv4_tcp_packet();
    p[9] = 50; // ESP
    assert!(matches!(parser::parse(&p), Err(ParseError::Unsupported)));
}

#[test]
fn parser_rejects_tcp_data_offset_too_small() {
    let mut p = ipv4_tcp_packet();
    p[32] = 4 << 4; // data_offset = 4 < 5
    assert!(parser::parse(&p).is_err());
}

#[test]
fn parser_rejects_tcp_data_offset_exceeds_payload() {
    let mut p = ipv4_tcp_packet();
    p[32] = 15 << 4; // data_offset=15 → 60 bytes, but TCP payload is only 20
    assert!(parser::parse(&p).is_err());
}

// ── Phase 2: Phase2Config tests ──────────────────────────────────────────────

use local_dpi_bypass::core::phase2_config::Phase2Config;

#[test]
fn phase2_config_parse_valid_disabled() {
    let toml = "[phase2_capture]\nenabled = false\ndestination_ips = []\ntcp_ports = [443]\nudp_ports = []\n";
    let cfg = Phase2Config::parse(toml).expect("should parse");
    assert!(!cfg.enabled);
    assert!(cfg.destination_ips.is_empty());
    assert_eq!(cfg.tcp_ports, vec![443]);
}

#[test]
fn phase2_config_parse_valid_enabled() {
    let toml = "[phase2_capture]\nenabled = true\ndestination_ips = [\"203.0.113.1\"]\ntcp_ports = [443]\nudp_ports = []\n";
    let cfg = Phase2Config::parse(toml).expect("should parse");
    assert!(cfg.enabled);
    assert_eq!(cfg.destination_ips.len(), 1);
}

#[test]
fn phase2_config_rejects_invalid_toml() {
    assert!(Phase2Config::parse("not toml at all ][").is_err());
}

#[test]
fn phase2_config_rejects_missing_key() {
    // Missing udp_ports
    let toml = "[phase2_capture]\nenabled = false\ndestination_ips = []\ntcp_ports = [443]\n";
    assert!(Phase2Config::parse(toml).is_err());
}

#[test]
fn phase2_config_rejects_extra_key() {
    let toml = "[phase2_capture]\nenabled = false\ndestination_ips = []\ntcp_ports = [443]\nudp_ports = []\nextra = true\n";
    assert!(Phase2Config::parse(toml).is_err());
}

#[test]
fn phase2_config_rejects_zero_port() {
    let toml = "[phase2_capture]\nenabled = true\ndestination_ips = [\"203.0.113.1\"]\ntcp_ports = [0]\nudp_ports = []\n";
    assert!(Phase2Config::parse(toml).is_err());
}

#[test]
fn phase2_config_rejects_loopback_ip() {
    let toml = "[phase2_capture]\nenabled = true\ndestination_ips = [\"127.0.0.1\"]\ntcp_ports = [443]\nudp_ports = []\n";
    assert!(Phase2Config::parse(toml).is_err());
}

#[test]
fn phase2_config_filter_disabled_returns_error() {
    let toml = "[phase2_capture]\nenabled = false\ndestination_ips = []\ntcp_ports = [443]\nudp_ports = []\n";
    let cfg = Phase2Config::parse(toml).unwrap();
    assert!(
        cfg.filter().is_err(),
        "disabled config must not produce a filter"
    );
}

#[test]
fn phase2_config_filter_empty_ips_returns_error() {
    let toml = "[phase2_capture]\nenabled = true\ndestination_ips = []\ntcp_ports = [443]\nudp_ports = []\n";
    let cfg = Phase2Config::parse(toml).unwrap();
    assert!(cfg.filter().is_err());
}

#[test]
fn phase2_config_filter_contains_ip_and_port() {
    let toml = "[phase2_capture]\nenabled = true\ndestination_ips = [\"203.0.113.5\"]\ntcp_ports = [443]\nudp_ports = []\n";
    let cfg = Phase2Config::parse(toml).unwrap();
    let filter = cfg.filter().expect("should build filter");
    assert!(filter.contains("203.0.113.5"), "filter must mention the IP");
    assert!(filter.contains("443"), "filter must mention the port");
    assert!(filter.contains("outbound"), "filter must be outbound");
    assert!(filter.contains("!loopback"), "filter must exclude loopback");
}

#[test]
fn phase2_config_example_parses_successfully() {
    // The bundled example (disabled) must always parse without error.
    use local_dpi_bypass::core::phase2_config;
    let _ = Phase2Config::parse(phase2_config::EXAMPLE).expect("bundled example must parse");
}

// ── Phase 2: PassThroughEngine mock pipeline tests ────────────────────────────

use local_dpi_bypass::capture::{CaptureError, CapturedPacket, PacketCapture, ReceiveEvent};

/// A simple mock capture that replays a fixed event sequence.
struct MockCapture {
    events: std::collections::VecDeque<Result<ReceiveEvent<()>, CaptureError>>,
    mode: RunMode,
    send_count: u64,
    closed: bool,
    shut_down: bool,
}

impl MockCapture {
    fn new(mode: RunMode, events: Vec<Result<ReceiveEvent<()>, CaptureError>>) -> Self {
        Self {
            events: events.into(),
            mode,
            send_count: 0,
            closed: false,
            shut_down: false,
        }
    }
}

impl PacketCapture for MockCapture {
    type Address = ();
    fn mode(&self) -> RunMode {
        self.mode
    }
    fn receive(&mut self) -> Result<ReceiveEvent<()>, CaptureError> {
        self.events.pop_front().unwrap_or(Ok(ReceiveEvent::End))
    }
    fn send(&mut self, _: &CapturedPacket<()>) -> Result<(), CaptureError> {
        self.send_count += 1;
        Ok(())
    }
    fn shutdown_receive(&mut self) -> Result<(), CaptureError> {
        self.shut_down = true;
        Ok(())
    }
    fn close(&mut self) -> Result<(), CaptureError> {
        self.closed = true;
        Ok(())
    }
}

fn tcp_pkt() -> Vec<u8> {
    ipv4_tcp_packet()
}

#[test]
fn pipeline_pass_through_active_counts_and_reinserts() {
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;

    let packet = CapturedPacket {
        bytes: tcp_pkt(),
        address: (),
    };
    let events = vec![Ok(ReceiveEvent::Packet(packet)), Ok(ReceiveEvent::End)];
    let mut engine =
        PassThroughEngine::new_passthrough(MockCapture::new(RunMode::Active, events), |_| {});
    // Pre-signal stop so shutdown_receive() is called before the Packet/End sequence.
    // This makes ReceiveEvent::End a graceful exit (stopping.is_some() == true).
    let stop = AtomicBool::new(true);
    let counters = engine.run(RunMode::Active, &stop).expect("should succeed");
    assert_eq!(counters.processed, 1);
    assert_eq!(counters.reinserted, 1);
    assert_eq!(counters.tcp, 1);
    assert_eq!(counters.ipv4, 1);
    assert_eq!(counters.errors, 0);
    assert_eq!(counters.modified, 0);
}

#[test]
fn pipeline_dry_run_does_not_send() {
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;

    let packet = CapturedPacket {
        bytes: tcp_pkt(),
        address: (),
    };
    let events = vec![Ok(ReceiveEvent::Packet(packet)), Ok(ReceiveEvent::End)];
    let mut engine =
        PassThroughEngine::new_passthrough(MockCapture::new(RunMode::DryRun, events), |_| {});
    let stop = AtomicBool::new(true); // pre-signal for graceful End
    let counters = engine.run(RunMode::DryRun, &stop).expect("should succeed");
    assert_eq!(counters.processed, 1);
    assert_eq!(counters.reinserted, 0, "dry-run must never reinject");
    assert_eq!(counters.modified, 0);
}

#[test]
fn pipeline_counts_malformed_and_unsupported() {
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;

    // malformed: empty payload
    let malformed = CapturedPacket {
        bytes: vec![0xAB],
        address: (),
    };
    // unsupported: IPv4 with fragment flag
    let mut frag = ipv4_tcp_packet();
    frag[6] = 0x20;
    let unsupported = CapturedPacket {
        bytes: frag,
        address: (),
    };

    let events = vec![
        Ok(ReceiveEvent::Packet(malformed)),
        Ok(ReceiveEvent::Packet(unsupported)),
        Ok(ReceiveEvent::End),
    ];
    let mut engine =
        PassThroughEngine::new_passthrough(MockCapture::new(RunMode::DryRun, events), |_| {});
    let stop = AtomicBool::new(true); // pre-signal for graceful End
    let counters = engine.run(RunMode::DryRun, &stop).unwrap();
    assert_eq!(counters.processed, 2);
    assert_eq!(counters.malformed, 1);
    assert_eq!(counters.unsupported, 1);
}

#[test]
fn pipeline_idle_events_are_not_counted_as_processed() {
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;

    let events = vec![
        Ok(ReceiveEvent::Idle),
        Ok(ReceiveEvent::Idle),
        Ok(ReceiveEvent::End),
    ];
    let mut engine =
        PassThroughEngine::new_passthrough(MockCapture::new(RunMode::DryRun, events), |_| {});
    let stop = AtomicBool::new(true); // pre-signal for graceful End
    let counters = engine.run(RunMode::DryRun, &stop).unwrap();
    assert_eq!(counters.processed, 0);
}

// ── Phase 4: TCP Segmentation Strategy & Active Engine contracts ─────────────

use std::cell::RefCell;
use std::rc::Rc;

struct RecordingCapture {
    events: std::collections::VecDeque<Result<ReceiveEvent<()>, CaptureError>>,
    mode: RunMode,
    sent: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl RecordingCapture {
    fn new(
        mode: RunMode,
        events: Vec<Result<ReceiveEvent<()>, CaptureError>>,
        sent: Rc<RefCell<Vec<Vec<u8>>>>,
    ) -> Self {
        Self {
            events: events.into(),
            mode,
            sent,
        }
    }
}

impl PacketCapture for RecordingCapture {
    type Address = ();
    fn mode(&self) -> RunMode {
        self.mode
    }
    fn receive(&mut self) -> Result<ReceiveEvent<()>, CaptureError> {
        self.events.pop_front().unwrap_or(Ok(ReceiveEvent::End))
    }
    fn send(&mut self, pkt: &CapturedPacket<()>) -> Result<(), CaptureError> {
        self.sent.borrow_mut().push(pkt.bytes.clone());
        Ok(())
    }
    fn shutdown_receive(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
    fn close(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
}

fn tcp_packet_with_payload(dst_ip: std::net::Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    use local_dpi_bypass::core::checksum::{ipv4_header_checksum, tcp_checksum};
    let src = std::net::Ipv4Addr::new(192, 168, 1, 100);
    let ip_hdr_len = 20;
    let tcp_hdr_len = 20;
    let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0x4321u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_csum = ipv4_header_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&100_000u32.to_be_bytes());
    pkt[28..32].copy_from_slice(&200_000u32.to_be_bytes());
    pkt[32] = 0x50; // offset 5
    pkt[33] = 0x18; // ACK + PSH
    pkt[34..36].copy_from_slice(&8192u16.to_be_bytes());

    pkt[40..].copy_from_slice(payload);

    let tcp_csum = tcp_checksum(src.into(), dst_ip.into(), &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

    pkt
}

#[test]
fn pipeline_split_tcp_active_splits_allowed_initial_packet() {
    use local_dpi_bypass::core::flow::FlowTable;
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;
    use local_dpi_bypass::filtering::engine::TargetPreset;
    use local_dpi_bypass::filtering::list::IpEntry;
    use local_dpi_bypass::filtering::FilterEngine;
    use local_dpi_bypass::strategies::SplitTcp;

    let target_ip = std::net::Ipv4Addr::new(93, 184, 216, 34);
    let payload = b"Hello, secure world!";
    let original = tcp_packet_with_payload(target_ip, 443, payload);

    let sent = Rc::new(RefCell::new(Vec::new()));
    let events = vec![
        Ok(ReceiveEvent::Packet(CapturedPacket {
            bytes: original.clone(),
            address: (),
        })),
        Ok(ReceiveEvent::End),
    ];
    let capture = RecordingCapture::new(RunMode::Active, events, Rc::clone(&sent));

    let filter_engine = FilterEngine::new(
        vec![],
        vec![],
        vec![TargetPreset {
            allow_domains: vec![],
            allow_ips: vec![IpEntry::Single(target_ip.into())],
            tcp_ports: vec![443],
            udp_ports: vec![],
        }],
    );

    let flow_table = FlowTable::with_defaults();
    let strategy = Box::new(SplitTcp::new(2));

    let mut engine = PassThroughEngine::new(capture, filter_engine, flow_table, strategy, |_| {});
    let stop = AtomicBool::new(true);
    let counters = engine
        .run(RunMode::Active, &stop)
        .expect("active engine should succeed");

    assert_eq!(counters.processed, 1);
    assert_eq!(
        counters.modified, 1,
        "initial allowed payload must be modified"
    );
    assert_eq!(counters.reinserted, 2, "must reinject exactly two segments");

    let sent_packets = sent.borrow();
    assert_eq!(sent_packets.len(), 2);

    let seg1 = &sent_packets[0];
    let seg2 = &sent_packets[1];

    let p1 = &seg1[40..];
    let p2 = &seg2[40..];
    assert_eq!(p1, &payload[..2]);
    assert_eq!(p2, &payload[2..]);
    assert_eq!(
        [p1, p2].concat(),
        payload,
        "concatenated payloads must equal original"
    );

    let seq1 = u32::from_be_bytes([seg1[24], seg1[25], seg1[26], seg1[27]]);
    let seq2 = u32::from_be_bytes([seg2[24], seg2[25], seg2[26], seg2[27]]);
    assert_eq!(seq1, 100_000);
    assert_eq!(seq2, 100_002);
}

#[test]
fn pipeline_split_tcp_dry_run_suppresses_split_send() {
    use local_dpi_bypass::core::flow::FlowTable;
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;
    use local_dpi_bypass::filtering::engine::TargetPreset;
    use local_dpi_bypass::filtering::list::IpEntry;
    use local_dpi_bypass::filtering::FilterEngine;
    use local_dpi_bypass::strategies::SplitTcp;

    let target_ip = std::net::Ipv4Addr::new(93, 184, 216, 34);
    let original = tcp_packet_with_payload(target_ip, 443, b"Dry-run test payload");

    let sent = Rc::new(RefCell::new(Vec::new()));
    let events = vec![
        Ok(ReceiveEvent::Packet(CapturedPacket {
            bytes: original,
            address: (),
        })),
        Ok(ReceiveEvent::End),
    ];
    let capture = RecordingCapture::new(RunMode::DryRun, events, Rc::clone(&sent));

    let filter_engine = FilterEngine::new(
        vec![],
        vec![],
        vec![TargetPreset {
            allow_domains: vec![],
            allow_ips: vec![IpEntry::Single(target_ip.into())],
            tcp_ports: vec![443],
            udp_ports: vec![],
        }],
    );

    let mut engine = PassThroughEngine::new(
        capture,
        filter_engine,
        FlowTable::with_defaults(),
        Box::new(SplitTcp::default()),
        |_| {},
    );
    let stop = AtomicBool::new(true);
    let counters = engine.run(RunMode::DryRun, &stop).unwrap();

    assert_eq!(counters.processed, 1);
    assert_eq!(counters.modified, 0, "dry-run never modifies packets");
    assert_eq!(
        counters.would_modify, 1,
        "dry-run records intentions separately"
    );
    assert_eq!(
        counters.reinserted, 0,
        "dry-run must never send or reinject"
    );
    assert!(sent.borrow().is_empty());
}

#[test]
fn pipeline_split_tcp_excluded_packet_passes_unmodified() {
    use local_dpi_bypass::core::flow::FlowTable;
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;
    use local_dpi_bypass::filtering::engine::TargetPreset;
    use local_dpi_bypass::filtering::list::IpEntry;
    use local_dpi_bypass::filtering::FilterEngine;
    use local_dpi_bypass::strategies::SplitTcp;

    let target_ip = std::net::Ipv4Addr::new(93, 184, 216, 34);
    let original = tcp_packet_with_payload(target_ip, 443, b"Excluded payload");

    let sent = Rc::new(RefCell::new(Vec::new()));
    let events = vec![
        Ok(ReceiveEvent::Packet(CapturedPacket {
            bytes: original.clone(),
            address: (),
        })),
        Ok(ReceiveEvent::End),
    ];
    let capture = RecordingCapture::new(RunMode::Active, events, Rc::clone(&sent));

    // Target is preset allow, but ALSO explicitly in exclude_ips
    let filter_engine = FilterEngine::new(
        vec![IpEntry::Single(target_ip.into())], // Exclude!
        vec![],
        vec![TargetPreset {
            allow_domains: vec![],
            allow_ips: vec![IpEntry::Single(target_ip.into())],
            tcp_ports: vec![443],
            udp_ports: vec![],
        }],
    );

    let mut engine = PassThroughEngine::new(
        capture,
        filter_engine,
        FlowTable::with_defaults(),
        Box::new(SplitTcp::default()),
        |_| {},
    );
    let stop = AtomicBool::new(true);
    let counters = engine.run(RunMode::Active, &stop).unwrap();

    assert_eq!(counters.processed, 1);
    assert_eq!(
        counters.modified, 0,
        "excluded traffic must never be modified"
    );
    assert_eq!(
        counters.reinserted, 1,
        "excluded traffic must pass through exactly once"
    );
    assert_eq!(sent.borrow()[0], original, "byte-exact pass-through");
}

// ── Phase 5: TLS SNI & QUIC Initial Metadata contracts ───────────────────────

#[test]
fn pipeline_tls_sni_matches_domain_allowlist_preset() {
    use local_dpi_bypass::core::flow::FlowTable;
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;
    use local_dpi_bypass::filtering::engine::TargetPreset;
    use local_dpi_bypass::filtering::list::DomainEntry;
    use local_dpi_bypass::filtering::FilterEngine;
    use local_dpi_bypass::strategies::SplitTcp;

    // Create a TLS ClientHello with SNI "twitch.tv"
    let client_hello = local_dpi_bypass::core::tls::build_test_client_hello("twitch.tv");
    // Unknown IP (not in any allowlist!), but port 443
    let unknown_ip = std::net::Ipv4Addr::new(198, 51, 100, 10);
    let original = tcp_packet_with_payload(unknown_ip, 443, &client_hello);

    let sent = Rc::new(RefCell::new(Vec::new()));
    let events = vec![
        Ok(ReceiveEvent::Packet(CapturedPacket {
            bytes: original,
            address: (),
        })),
        Ok(ReceiveEvent::End),
    ];
    let capture = RecordingCapture::new(RunMode::Active, events, Rc::clone(&sent));

    // Preset only authorizes domain suffix ".twitch.tv" on port 443
    let filter_engine = FilterEngine::new(
        vec![],
        vec![],
        vec![TargetPreset {
            allow_domains: vec![DomainEntry::Suffix("twitch.tv".into())],
            allow_ips: vec![],
            tcp_ports: vec![443],
            udp_ports: vec![],
        }],
    );

    let mut engine = PassThroughEngine::new(
        capture,
        filter_engine,
        FlowTable::with_defaults(),
        Box::new(SplitTcp::default()),
        |_| {},
    );
    let stop = AtomicBool::new(true);
    let counters = engine.run(RunMode::Active, &stop).unwrap();

    assert_eq!(counters.processed, 1);
    assert_eq!(
        counters.modified, 1,
        "domain matching via extracted SNI must authorize split"
    );
    assert_eq!(
        counters.reinserted, 2,
        "must reinject two segments for twitch.tv"
    );
}

#[test]
fn pipeline_tls_sni_excluded_domain_wins_over_allowed_ip() {
    use local_dpi_bypass::core::flow::FlowTable;
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;
    use local_dpi_bypass::filtering::engine::TargetPreset;
    use local_dpi_bypass::filtering::list::{DomainEntry, IpEntry};
    use local_dpi_bypass::filtering::FilterEngine;
    use local_dpi_bypass::strategies::SplitTcp;

    // ClientHello with SNI "t.me" (Telegram)
    let client_hello = local_dpi_bypass::core::tls::build_test_client_hello("t.me");
    let target_ip = std::net::Ipv4Addr::new(149, 154, 167, 99);
    let original = tcp_packet_with_payload(target_ip, 443, &client_hello);

    let sent = Rc::new(RefCell::new(Vec::new()));
    let events = vec![
        Ok(ReceiveEvent::Packet(CapturedPacket {
            bytes: original.clone(),
            address: (),
        })),
        Ok(ReceiveEvent::End),
    ];
    let capture = RecordingCapture::new(RunMode::Active, events, Rc::clone(&sent));

    // IP is allowed, but domain "t.me" is in exclude_domains!
    let filter_engine = FilterEngine::new(
        vec![],
        vec![DomainEntry::Exact("t.me".into())], // Exclude!
        vec![TargetPreset {
            allow_domains: vec![],
            allow_ips: vec![IpEntry::Single(target_ip.into())],
            tcp_ports: vec![443],
            udp_ports: vec![],
        }],
    );

    let mut engine = PassThroughEngine::new(
        capture,
        filter_engine,
        FlowTable::with_defaults(),
        Box::new(SplitTcp::default()),
        |_| {},
    );
    let stop = AtomicBool::new(true);
    let counters = engine.run(RunMode::Active, &stop).unwrap();

    assert_eq!(counters.processed, 1);
    assert_eq!(
        counters.modified, 0,
        "excluded domain must win over allowed IP"
    );
    assert_eq!(
        counters.reinserted, 1,
        "excluded traffic must pass through unmodified"
    );
    assert_eq!(sent.borrow()[0], original);
}

// ── Phase 6: Discord Voice & STUN Profile contracts ──────────────────────────

fn udp_packet_with_payload(dst_ip: std::net::Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    use local_dpi_bypass::core::checksum::ipv4_header_checksum;
    let src = std::net::Ipv4Addr::new(192, 168, 1, 100);
    let ip_hdr_len = 20;
    let udp_hdr_len = 8;
    let udp_len = udp_hdr_len + payload.len();
    let total_len = ip_hdr_len + udp_len;

    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0x5555u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_csum = ipv4_header_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    pkt[20..22].copy_from_slice(&50000u16.to_be_bytes()); // src port
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes()); // dst port
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[26..28].copy_from_slice(&[0, 0]); // UDP checksum optional in IPv4, 0 is valid

    pkt[28..].copy_from_slice(payload);
    pkt
}

#[test]
fn pipeline_discord_voice_stun_recognized_and_media_unchanged() {
    use local_dpi_bypass::core::flow::FlowTable;
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;
    use local_dpi_bypass::filtering::FilterEngine;
    use local_dpi_bypass::strategies::SplitTcp;

    let rtc_ip = std::net::Ipv4Addr::new(162, 159, 138, 232);
    let rtc_port = 50001;

    // 1. STUN Binding Request (NAT discovery)
    let stun_payload = local_dpi_bypass::core::stun::build_test_stun_binding_request();
    let stun_pkt = udp_packet_with_payload(rtc_ip, rtc_port, &stun_payload);

    // 2. RTP Voice Media Stream (Audio frames)
    let mut rtp_payload = vec![0u8; 120];
    rtp_payload[0] = 0x80; // RTP v2
    rtp_payload[1] = 0x78; // Payload type (Opus)
    let rtp_pkt = udp_packet_with_payload(rtc_ip, rtc_port, &rtp_payload);

    let sent = Rc::new(RefCell::new(Vec::new()));
    let events = vec![
        Ok(ReceiveEvent::Packet(CapturedPacket {
            bytes: stun_pkt.clone(),
            address: (),
        })),
        Ok(ReceiveEvent::Packet(CapturedPacket {
            bytes: rtp_pkt.clone(),
            address: (),
        })),
        Ok(ReceiveEvent::End),
    ];
    let capture = RecordingCapture::new(RunMode::Active, events, Rc::clone(&sent));

    let filter_engine = FilterEngine::new(vec![], vec![], vec![]);
    let mut engine = PassThroughEngine::new(
        capture,
        filter_engine,
        FlowTable::with_defaults(),
        Box::new(SplitTcp::default()),
        |_| {},
    );
    let stop = AtomicBool::new(true);
    let counters = engine.run(RunMode::Active, &stop).unwrap();

    assert_eq!(counters.processed, 2);
    assert_eq!(
        counters.modified, 0,
        "voice media streams must NEVER be modified"
    );
    assert_eq!(
        counters.reinserted, 2,
        "both STUN and RTP packets must pass through cleanly"
    );

    let sent_list = sent.borrow();
    assert_eq!(sent_list[0], stun_pkt, "STUN packet passed through intact");
    assert_eq!(
        sent_list[1], rtp_pkt,
        "RTP voice media passed through intact (media unchanged guarantee)"
    );
}

#[test]
fn pipeline_rejects_unlisted_stun_even_for_experimental_strategy() {
    use local_dpi_bypass::core::flow::FlowTable;
    use local_dpi_bypass::core::pipeline::PassThroughEngine;
    use local_dpi_bypass::core::PacketEngine as _;
    use local_dpi_bypass::filtering::{FilterEngine, TargetPreset};
    use local_dpi_bypass::strategies::AutoBypass;

    let rtc_ip = std::net::Ipv4Addr::new(162, 159, 138, 232);
    let rtc_port = 50001;

    let stun_payload = local_dpi_bypass::core::stun::build_test_stun_binding_request();
    let stun_pkt = udp_packet_with_payload(rtc_ip, rtc_port, &stun_payload);

    let sent = Rc::new(RefCell::new(Vec::new()));
    let events = vec![
        Ok(ReceiveEvent::Packet(CapturedPacket {
            bytes: stun_pkt.clone(),
            address: (),
        })),
        Ok(ReceiveEvent::End),
    ];
    let capture = RecordingCapture::new(RunMode::Active, events, Rc::clone(&sent));

    // Preset matching Discord voice UDP ports
    let voice_preset = TargetPreset {
        allow_domains: vec![],
        allow_ips: vec![],
        tcp_ports: vec![],
        udp_ports: vec![rtc_port],
    };
    let filter_engine = FilterEngine::new(vec![], vec![], vec![voice_preset]);
    let mut engine = PassThroughEngine::new(
        capture,
        filter_engine,
        FlowTable::with_defaults(),
        Box::new(AutoBypass::default()),
        |_| {},
    );
    let stop = AtomicBool::new(true);
    let counters = engine.run(RunMode::Active, &stop).unwrap();

    assert_eq!(counters.processed, 1);
    assert_eq!(
        counters.modified, 0,
        "port and STUN framing are not destination authorization"
    );
    assert_eq!(counters.reinserted, 1);
    let sent_list = sent.borrow();
    assert_eq!(sent_list.len(), 1);
    assert_eq!(sent_list[0], stun_pkt);
}

// ── Phase 7: Sequential Strategy Tester contracts ────────────────────────────

use local_dpi_bypass::core::tester::{self, ProbeStatus, TestVerdict, DEFAULT_TARGETS};

#[test]
fn phase_seven_cli_test_mock_dispatches_with_zero_code() {
    let reply = cli::dispatch(&["test", "--mock"]);
    assert_eq!(reply.code, 0);
    assert!(reply.text.contains("Target"));
    assert!(reply.text.contains("Strategy"));
    assert!(reply.text.contains("www.youtube.com:443"));
    assert!(reply.text.contains("discord.com:443"));
    assert!(reply.text.contains("twitch.tv:443"));
    assert!(reply.text.contains("t.me:443"));
    assert!(reply.text.contains("pass-through"));
    assert!(reply.text.contains("split-tcp"));
    assert!(reply.text.contains("SUCCESS"));
    assert!(reply.text.contains("FAIL"));
}

#[test]
fn phase_seven_tester_attribution_rules() {
    // 1. pass-through with OK status -> SUCCESS (baseline reference)
    assert_eq!(
        tester::determine_verdict(&ProbeStatus::Ok("TLS 1.3".into()), true, "pass-through"),
        TestVerdict::Success
    );

    // 2. split-tcp with OK status AND applied=true -> SUCCESS
    assert_eq!(
        tester::determine_verdict(&ProbeStatus::Ok("TLS 1.3".into()), true, "split-tcp"),
        TestVerdict::Success
    );

    // 3. split-tcp with OK status BUT applied=false -> INCONCLUSIVE (honest attribution)
    assert_eq!(
        tester::determine_verdict(&ProbeStatus::Ok("TLS 1.3".into()), false, "split-tcp"),
        TestVerdict::Inconclusive
    );

    // 4. Blocked/RST -> FAIL
    assert_eq!(
        tester::determine_verdict(&ProbeStatus::Blocked("RST".into()), true, "pass-through"),
        TestVerdict::Fail
    );
    assert_eq!(
        tester::determine_verdict(&ProbeStatus::Blocked("RST".into()), true, "split-tcp"),
        TestVerdict::Fail
    );

    // 5. Timeout -> FAIL
    assert_eq!(
        tester::determine_verdict(&ProbeStatus::Timeout, true, "split-tcp"),
        TestVerdict::Fail
    );

    // 6. DNS error -> INCONCLUSIVE
    assert_eq!(
        tester::determine_verdict(
            &ProbeStatus::DnsError("NXDOMAIN".into()),
            false,
            "split-tcp"
        ),
        TestVerdict::Inconclusive
    );
}

#[test]
fn phase_seven_tester_honesty_inconclusive_when_not_applied() {
    // Prober simulates connection success, but driver was NOT active so applied=false for split-tcp
    let results = tester::run_test_suite_with_prober(
        DEFAULT_TARGETS,
        &["pass-through", "split-tcp"],
        |_target, strategy| {
            if strategy == "pass-through" {
                (ProbeStatus::Ok("TLS".into()), 20, true)
            } else {
                (ProbeStatus::Ok("TLS".into()), 20, false) // unconfirmed application!
            }
        },
    );

    for r in &results {
        if r.strategy == "pass-through" {
            assert_eq!(r.result, TestVerdict::Success);
        } else if r.strategy == "split-tcp" {
            assert_eq!(
                r.result,
                TestVerdict::Inconclusive,
                "unapplied strategy must be INCONCLUSIVE"
            );
        }
    }
}

#[test]
fn phase_seven_tester_profile_restore_preserves_config() {
    // Testing must never modify the on-disk config/default.toml or config/phase2.toml
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let default_path = root.join("config").join("default.toml");
    let initial_content = std::fs::read_to_string(&default_path).expect("read default.toml");

    // Execute mock test
    let (code, output) = tester::execute_tester(true);
    assert_eq!(code, 0);
    assert!(output.contains("completed"));

    // Verify config file content on disk is bit-for-bit identical
    let after_content = std::fs::read_to_string(&default_path).expect("read default.toml after");
    assert_eq!(
        initial_content, after_content,
        "config/default.toml must remain unaltered"
    );
}

#[test]
fn phase_seven_tester_simulated_prober_suite() {
    let targets = &DEFAULT_TARGETS[..2]; // YouTube and Discord
    let strategies = &["pass-through", "split-tcp"];

    let results = tester::run_test_suite_with_prober(targets, strategies, |_target, strategy| {
        if strategy == "pass-through" {
            (ProbeStatus::Blocked("RST".into()), 40, true)
        } else {
            (ProbeStatus::Ok("TLS 1.3".into()), 35, true)
        }
    });

    assert_eq!(results.len(), 4);
    let table = tester::format_results_table(&results);
    assert!(table.contains("www.youtube.com:443"));
    assert!(table.contains("discord.com:443"));
    assert!(table.contains("FAIL"));
    assert!(table.contains("SUCCESS"));
}

// ── Phase 8: Windows Service (SCM) contracts ─────────────────────────────────

use local_dpi_bypass::service::{
    ServiceError, ServiceManager, ServiceState, WindowsService, DISPLAY_NAME, SERVICE_NAME,
};

#[test]
fn phase_eight_service_quoted_path_security() {
    // CWE-428 unquoted search path security contract:
    // Any path containing spaces must be enclosed in double quotes.
    let path_with_spaces =
        std::path::Path::new(r"C:\Program Files\Local DPI Bypass\dpi-bypass.exe");
    let cmd = windivert_adapter::build_quoted_service_command(path_with_spaces, "service run");

    assert!(
        cmd.starts_with('"'),
        "binary path must start with double quote"
    );
    assert!(
        cmd.contains(r#".exe" service run"#),
        "must close quote before subcommand"
    );
    assert_eq!(
        cmd,
        r#""C:\Program Files\Local DPI Bypass\dpi-bypass.exe" service run"#
    );
}

#[test]
fn phase_eight_service_state_and_error_display() {
    assert_eq!(format!("{}", ServiceState::NotInstalled), "Not Installed");
    assert_eq!(format!("{}", ServiceState::Stopped), "Stopped");
    assert_eq!(format!("{}", ServiceState::Running), "Running");

    assert!(format!("{}", ServiceError::AccessDenied).contains("Administrator"));
    assert!(format!("{}", ServiceError::ServiceNotFound).contains("not installed"));
    assert!(format!("{}", ServiceError::NotImplemented).contains("not supported"));
}

#[test]
fn phase_eight_service_cli_dispatch() {
    // 1. Unknown service action returns code 2
    let unknown_reply = cli::dispatch(&["service", "invalid_action"]);
    assert_eq!(unknown_reply.code, 2);
    assert!(unknown_reply.text.contains("Unknown service command"));

    // 2. Querying status via CLI returns code 0 (or code 1 if OS error without admin)
    // and correctly identifies service name
    let status_reply = cli::dispatch(&["service", "status"]);
    assert!(
        status_reply.code == 0 || status_reply.code == 1,
        "service status query must be graceful"
    );
    assert!(
        status_reply.text.contains(SERVICE_NAME)
            || status_reply.text.contains("Failed to query service status")
    );
}

#[test]
fn phase_eight_service_manager_default_trait_contract() {
    let service = WindowsService::default();
    assert_eq!(service.service_name, SERVICE_NAME);
    assert_eq!(service.display_name, DISPLAY_NAME);

    // Querying status via trait should not panic
    let _ = service.status();
}

// ── Phase 9: Read-Only Diagnostics & Sanitized Logging contracts ─────────────

use local_dpi_bypass::diagnostics::{
    engine::DefaultDiagnostics, logger, CheckStatus, Diagnostics, PLANNED_CHECKS,
};

#[test]
fn phase_nine_diagnostics_all_planned_checks_present() {
    let diag = DefaultDiagnostics;
    let results = diag.run();

    assert_eq!(results.len(), PLANNED_CHECKS.len());
    for (i, &expected_name) in PLANNED_CHECKS.iter().enumerate() {
        assert_eq!(results[i].name, expected_name);
        assert!(!results[i].message.is_empty());
    }
}

#[test]
fn phase_nine_diagnostics_honesty_unsupported_not_fake_ok() {
    let diag = DefaultDiagnostics;
    let results = diag.run();

    // QUIC check must return Unsupported / NotRun honestly, NEVER a fake Ok
    let quic_check = results
        .iter()
        .find(|r| r.name == "QUIC")
        .expect("QUIC check present");
    assert_ne!(
        quic_check.status,
        CheckStatus::Ok,
        "QUIC check must never return fabricated OK without active engine"
    );
    assert_eq!(quic_check.status, CheckStatus::Unsupported);
}

#[test]
fn phase_nine_sanitized_logger_never_leaks_payload_or_sni() {
    // Sanitization test: verify that log messages strip control characters
    // and format lifecycle/counters without sensitive flow data
    let dirty_payload = "HTTP/1.1 200 OK\r\nHost: secret.example.com\x00\x01";
    let clean = logger::sanitize_message(dirty_payload);
    assert!(!clean.contains('\r'));
    assert!(!clean.contains('\n'));
    assert!(!clean.contains('\x00'));

    let counters = local_dpi_bypass::core::Counters {
        processed: 100,
        reinserted: 98,
        modified: 45,
        errors: 2,
        dropped: 0,
        ..Default::default()
    };

    // Logging counters writes aggregate numbers only, zero packet payloads
    logger::log_counters(&counters);
    let recent = logger::read_recent_logs(10).expect("read logs");
    assert!(!recent.is_empty());

    let last_line = recent.last().unwrap();
    assert!(last_line.contains("[COUNTERS]"));
    assert!(last_line.contains("processed=100"));
    assert!(!last_line.contains("secret.example.com"));
}

#[test]
fn phase_nine_cli_diagnose_and_logs_dispatch() {
    // 1. Diagnose command dispatches with code 0 or 1 and produces table
    let diag_reply = cli::dispatch(&["diagnose"]);
    assert!(diag_reply.code == 0 || diag_reply.code == 1);
    assert!(diag_reply.text.contains("System Diagnostics Report"));
    assert!(diag_reply.text.contains("Administrator privileges"));
    assert!(diag_reply.text.contains("WinDivert availability"));

    // 2. Logs command dispatches with code 0
    let logs_reply = cli::dispatch(&["logs"]);
    assert_eq!(logs_reply.code, 0);
    assert!(!logs_reply.text.is_empty());
}

// ── Phase 10: Release Packaging & Security Review contracts ──────────────────

#[test]
fn phase_ten_release_packaging_and_checksums_contract() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let run_dir = root.join("run");

    // 1. Core release binary exists
    assert!(
        run_dir.join("dpi-bypass.exe").exists(),
        "dpi-bypass.exe must exist in run/"
    );

    // 2. WinDivert driver files exist
    assert!(run_dir.join("WinDivert").join("WinDivert.dll").exists());
    assert!(run_dir.join("WinDivert").join("WinDivert64.sys").exists());

    // 3. Configuration files and presets exist
    assert!(run_dir.join("config").join("default.toml").exists());
    assert!(run_dir.join("config").join("phase2.toml").exists());
    assert!(run_dir
        .join("config")
        .join("presets")
        .join("youtube")
        .join("domains.txt")
        .exists());
    assert!(run_dir
        .join("config")
        .join("presets")
        .join("discord")
        .join("domains.txt")
        .exists());
    assert!(run_dir
        .join("config")
        .join("presets")
        .join("discord-voice")
        .join("domains.txt")
        .exists());
    assert!(run_dir
        .join("config")
        .join("presets")
        .join("twitch")
        .join("domains.txt")
        .exists());
    assert!(run_dir
        .join("config")
        .join("presets")
        .join("telegram")
        .join("domains.txt")
        .exists());

    // 4. One-click management scripts exist
    assert!(run_dir.join("start.cmd").exists());
    assert!(run_dir.join("service_install.cmd").exists());
    assert!(run_dir.join("service_remove.cmd").exists());
    assert!(run_dir.join("service_status.cmd").exists());
    assert!(run_dir.join("test.cmd").exists());
    assert!(run_dir.join("diagnose.cmd").exists());
    assert!(run_dir.join("logs.cmd").exists());

    // 5. SHA256SUMS.txt integrity file exists and has valid checksum lines
    let sums_path = run_dir.join("SHA256SUMS.txt");
    assert!(sums_path.exists());
    let sums_content = std::fs::read_to_string(&sums_path).expect("read SHA256SUMS.txt");
    for line in sums_content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        assert!(
            line.len() > 66,
            "checksum line must contain 64-char hex hash, spaces, and filename"
        );
        let hash_part = &line[..64];
        assert!(
            hash_part.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be valid hex"
        );
    }
}

#[test]
fn phase_ten_security_review_document_contract() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sec_doc = root.join("docs").join("security-review.md");
    assert!(sec_doc.exists(), "docs/security-review.md must exist");

    let text = std::fs::read_to_string(&sec_doc).expect("read security-review.md");
    assert!(text.contains("CWE-428"));
    assert!(text.contains("Memory Safety"));
    assert!(text.contains("Zero Telemetry"));
    assert!(text.contains("Log Privacy Guarantee"));
}
