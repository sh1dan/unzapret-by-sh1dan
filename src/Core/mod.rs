use std::net::IpAddr;

use crate::filtering::FilterDecision;

pub mod checksum;
pub mod config;
pub mod config_loader;
pub mod flow;
pub mod parser;
pub mod payloads;
pub mod phase2_config;
pub mod pipeline;
pub mod quic;
pub mod segment;
pub mod stun;
pub mod tester;
pub mod tls;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialMetadata {
    Unknown,
    TlsClientHello,
    QuicInitial { version: u32 },
    Stun,
}

/// Parsed, bounded view. Never derive Debug: metadata can include private hosts.
/// SNI is optional: encrypted ClientHello and fragmented records may hide it.
pub struct PacketContext<'a> {
    pub packet: &'a [u8],
    pub destination: IpAddr,
    pub destination_port: u16,
    pub transport: Transport,
    pub server_name: Option<&'a str>,
    pub initial: InitialMetadata,
    pub initial_payload: bool,
    pub filter: FilterDecision,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub processed: u64,
    pub eligible: u64,
    pub modified: u64,
    pub would_modify: u64,
    pub errors: u64,
    pub reinserted: u64,
    pub receive_errors: u64,
    pub send_errors: u64,
    /// Known user-mode losses only; driver queue drops cannot be measured here.
    pub dropped: u64,
    pub unsupported: u64,
    pub malformed: u64,
    pub tcp: u64,
    pub udp: u64,
    pub ipv4: u64,
    pub ipv6: u64,
}

impl std::fmt::Display for Counters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "processed={} eligible={} reinserted={} modified={} would_modify={} tcp={} udp={} errors={} receive_errors={} send_errors={} dropped={}",
            self.processed, self.eligible, self.reinserted, self.modified, self.would_modify,
            self.tcp, self.udp, self.errors, self.receive_errors, self.send_errors, self.dropped)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    Active,
    DryRun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineError {
    NotImplemented,
    Capture(crate::capture::CaptureError),
    InvalidConfiguration,
}

/// Adapter owns capture lifetime and per-flow state; callers own shutdown.
/// Future run implementation must stop receiving and drain before closing.
pub trait PacketEngine {
    fn run(
        &mut self,
        mode: RunMode,
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<Counters, EngineError>;
    fn counters(&self) -> Counters;
}

/// Explicitly unavailable; it cannot accidentally open a capture handle.
#[derive(Default)]
pub struct UnavailableEngine;

impl PacketEngine for UnavailableEngine {
    fn run(
        &mut self,
        _: RunMode,
        _: &std::sync::atomic::AtomicBool,
    ) -> Result<Counters, EngineError> {
        Err(EngineError::NotImplemented)
    }

    fn counters(&self) -> Counters {
        Counters::default()
    }
}
