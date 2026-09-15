//! Bounded per-flow state for initial-payload classification.
//! Flow key: (src_ip, dst_ip, src_port, dst_port, transport).
//! Limits: 4096 simultaneous flows, idle eviction after 30 s,
//!         at most 4 initial-payload packets per flow.
//!
//! When the table is full, new flows are classified Unknown (not AllowModify).
//! Payload retransmissions currently consume budget; sequence reassembly is not implemented.
//! This module does NOT touch packet bytes; it only tracks counters and timestamps.

use crate::core::Transport;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Uniquely identifies a unidirectional flow.
/// Not Debug: contains network endpoints.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub transport: Transport,
}

/// Per-flow tracking state.
struct FlowState {
    /// Number of initial-payload packets already observed.
    initial_count: u8,
    last_seen: Instant,
}

pub struct FlowTable {
    flows: HashMap<FlowKey, FlowState>,
    max_flows: usize,
    idle_timeout: Duration,
    max_initial_pkts: u8,
}

/// Classification result from the flow table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowClassification {
    /// This is an initial-payload packet — strategy may inspect it.
    InitialPayload,
    /// This flow has exceeded its initial-packet budget.
    LaterPayload,
    /// Table is full; new flow could not be registered.
    TableFull,
}

impl FlowTable {
    pub fn new(max_flows: usize, idle_timeout: Duration, max_initial_pkts: u8) -> Self {
        Self {
            flows: HashMap::with_capacity(max_flows.min(4096)),
            max_flows,
            idle_timeout,
            max_initial_pkts,
        }
    }

    /// Returns a FlowTable with the default Phase 3 limits.
    pub fn with_defaults() -> Self {
        Self::new(4096, Duration::from_secs(30), 4)
    }

    /// Classify a packet and update flow state.
    /// Evicts idle flows on every call; caller should call `evict_idle` periodically
    /// if no packets arrive for a long time.
    pub fn classify(&mut self, key: FlowKey) -> FlowClassification {
        let now = Instant::now();

        // Evict idle entries first so full-table rejections are not spurious.
        self.evict_idle_at(now);

        if let Some(state) = self.flows.get_mut(&key) {
            state.last_seen = now;
            if state.initial_count < self.max_initial_pkts {
                state.initial_count += 1;
                return FlowClassification::InitialPayload;
            }
            return FlowClassification::LaterPayload;
        }

        // New flow.
        if self.flows.len() >= self.max_flows {
            return FlowClassification::TableFull;
        }
        self.flows.insert(
            key,
            FlowState {
                initial_count: 1,
                last_seen: now,
            },
        );
        FlowClassification::InitialPayload
    }

    /// Evict all flows that have been idle longer than `idle_timeout`.
    pub fn evict_idle(&mut self) {
        self.evict_idle_at(Instant::now());
    }

    fn evict_idle_at(&mut self, now: Instant) {
        self.flows
            .retain(|_, state| now.duration_since(state.last_seen) < self.idle_timeout);
    }

    /// Number of currently active flows (after eviction).
    pub fn active_flows(&mut self) -> usize {
        self.evict_idle();
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(src_port: u16) -> FlowKey {
        FlowKey {
            src: "10.0.0.1".parse().unwrap(),
            dst: "203.0.113.1".parse().unwrap(),
            src_port,
            dst_port: 443,
            transport: Transport::Tcp,
        }
    }

    #[test]
    fn first_four_packets_are_initial() {
        let mut table = FlowTable::new(128, Duration::from_secs(30), 4);
        let k = key(1234);
        assert_eq!(
            table.classify(k.clone()),
            FlowClassification::InitialPayload
        );
        assert_eq!(
            table.classify(k.clone()),
            FlowClassification::InitialPayload
        );
        assert_eq!(
            table.classify(k.clone()),
            FlowClassification::InitialPayload
        );
        assert_eq!(
            table.classify(k.clone()),
            FlowClassification::InitialPayload
        );
        assert_eq!(table.classify(k.clone()), FlowClassification::LaterPayload);
    }

    #[test]
    fn different_src_ports_are_different_flows() {
        let mut table = FlowTable::with_defaults();
        assert_eq!(table.classify(key(100)), FlowClassification::InitialPayload);
        assert_eq!(table.classify(key(101)), FlowClassification::InitialPayload);
        // Each is its own first packet.
        assert_eq!(table.classify(key(100)), FlowClassification::InitialPayload);
    }

    #[test]
    fn table_full_returns_table_full() {
        let mut table = FlowTable::new(2, Duration::from_secs(30), 4);
        // Fill both slots.
        assert_ne!(table.classify(key(1)), FlowClassification::TableFull);
        assert_ne!(table.classify(key(2)), FlowClassification::TableFull);
        // Third new flow → table full.
        assert_eq!(table.classify(key(3)), FlowClassification::TableFull);
    }

    #[test]
    fn idle_flows_are_evicted() {
        let mut table = FlowTable::new(2, Duration::from_millis(1), 4);
        table.classify(key(1));
        table.classify(key(2));
        std::thread::sleep(Duration::from_millis(5));
        // After eviction the table has room again.
        assert_ne!(table.classify(key(3)), FlowClassification::TableFull);
    }
}
