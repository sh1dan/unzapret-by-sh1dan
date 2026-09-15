//! Combined / Auto bypass strategy (Flowseal / Zapret profile).
//! Handles both TCP (Split-TCP) and UDP (Fake STUN / Discord Voice & QUIC Desync).

use super::{FakeUdpType, ProcessResult, Strategy};
use crate::core::{InitialMetadata, PacketContext, Transport};
use crate::filtering::FilterDecision;

#[derive(Clone, Debug)]
pub struct AutoBypass {
    pub split_offset: usize,
    pub udp_repeats: usize,
}

impl AutoBypass {
    pub fn new(split_offset: usize, udp_repeats: usize) -> Self {
        Self {
            split_offset: if split_offset == 0 { 2 } else { split_offset },
            udp_repeats: if udp_repeats == 0 { 6 } else { udp_repeats },
        }
    }
}

impl Default for AutoBypass {
    fn default() -> Self {
        Self::new(2, 6)
    }
}

impl Strategy for AutoBypass {
    fn name(&self) -> &'static str {
        "auto"
    }

    fn matches(&self, context: &PacketContext<'_>) -> bool {
        if context.filter != FilterDecision::Allow || !context.initial_payload {
            return false;
        }
        match context.transport {
            Transport::Tcp => true,
            Transport::Udp => {
                let port = context.destination_port;
                let is_voice_port =
                    (19294..=19344).contains(&port) || (50000..=50100).contains(&port);
                let is_stun = context.initial == InitialMetadata::Stun;
                let is_quic =
                    matches!(context.initial, InitialMetadata::QuicInitial { .. }) || port == 443;
                is_voice_port || is_stun || is_quic
            }
        }
    }

    fn process(&self, context: &PacketContext<'_>) -> ProcessResult {
        if !self.matches(context) {
            return ProcessResult::PassThrough;
        }
        match context.transport {
            Transport::Tcp => ProcessResult::SplitTcp {
                payload_offset: self.split_offset,
            },
            Transport::Udp => {
                let port = context.destination_port;
                let is_voice_port =
                    (19294..=19344).contains(&port) || (50000..=50100).contains(&port);
                let is_stun = context.initial == InitialMetadata::Stun;
                if is_voice_port || is_stun {
                    ProcessResult::FakeUdp {
                        payload_type: FakeUdpType::DiscordVoice,
                        repeats: self.udp_repeats,
                    }
                } else {
                    ProcessResult::FakeUdp {
                        payload_type: FakeUdpType::Quic,
                        repeats: self.udp_repeats,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_matches_allowed_tcp_and_udp_voice() {
        let strat = AutoBypass::default();
        let tcp_ctx = PacketContext {
            packet: &[],
            destination: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
            destination_port: 443,
            transport: Transport::Tcp,
            server_name: None,
            initial: InitialMetadata::TlsClientHello,
            initial_payload: true,
            filter: FilterDecision::Allow,
        };
        assert_eq!(
            strat.process(&tcp_ctx),
            ProcessResult::SplitTcp { payload_offset: 2 }
        );

        let udp_voice_ctx = PacketContext {
            packet: &[],
            destination: std::net::IpAddr::V4(std::net::Ipv4Addr::new(162, 159, 138, 232)),
            destination_port: 50001,
            transport: Transport::Udp,
            server_name: None,
            initial: InitialMetadata::Stun,
            initial_payload: true,
            filter: FilterDecision::Allow,
        };
        assert_eq!(
            strat.process(&udp_voice_ctx),
            ProcessResult::FakeUdp {
                payload_type: FakeUdpType::DiscordVoice,
                repeats: 6,
            }
        );
    }
}
