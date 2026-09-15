//! TCP Segmentation strategy (Phase 4).
//! Proposes splitting initial client TCP payload into two segments
//! at a configurable byte offset (default 2 bytes).

use super::{ProcessResult, Strategy};
use crate::core::{PacketContext, Transport};
use crate::filtering::FilterDecision;

#[derive(Clone, Debug)]
pub struct SplitTcp {
    pub split_offset: usize,
}

impl SplitTcp {
    pub fn new(split_offset: usize) -> Self {
        Self {
            split_offset: if split_offset == 0 { 2 } else { split_offset },
        }
    }
}

impl Default for SplitTcp {
    fn default() -> Self {
        Self::new(2)
    }
}

impl Strategy for SplitTcp {
    fn name(&self) -> &'static str {
        "split-tcp"
    }

    fn matches(&self, context: &PacketContext<'_>) -> bool {
        context.filter == FilterDecision::Allow
            && context.initial_payload
            && context.transport == Transport::Tcp
    }

    fn process(&self, context: &PacketContext<'_>) -> ProcessResult {
        if !self.matches(context) {
            return ProcessResult::PassThrough;
        }
        ProcessResult::SplitTcp {
            payload_offset: self.split_offset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_tcp_matches_only_allowed_initial_tcp() {
        let strat = SplitTcp::default();
        let allowed_initial = PacketContext {
            packet: &[],
            destination: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            destination_port: 443,
            transport: Transport::Tcp,
            server_name: None,
            initial: crate::core::InitialMetadata::Unknown,
            initial_payload: true,
            filter: FilterDecision::Allow,
        };
        assert!(strat.matches(&allowed_initial));
        assert_eq!(
            strat.process(&allowed_initial),
            ProcessResult::SplitTcp { payload_offset: 2 }
        );

        let excluded = PacketContext {
            filter: FilterDecision::Exclude,
            ..allowed_initial
        };
        assert!(!strat.matches(&excluded));
        assert_eq!(strat.process(&excluded), ProcessResult::PassThrough);

        let not_initial = PacketContext {
            initial_payload: false,
            ..allowed_initial
        };
        assert!(!strat.matches(&not_initial));
        assert_eq!(strat.process(&not_initial), ProcessResult::PassThrough);

        let udp = PacketContext {
            transport: Transport::Udp,
            ..allowed_initial
        };
        assert!(!strat.matches(&udp));
        assert_eq!(strat.process(&udp), ProcessResult::PassThrough);
    }
}
