//! Allowlist/exclude filter engine.
//! Evaluation order (first matching rule wins):
//!   1. Packet malformed/unsupported → pass-through (not our concern here)
//!   2. IP in exclude_ips             → Exclude
//!   3. Domain in exclude_domains     → Exclude  (if SNI visible)
//!   4. Domain exclusions configured but SNI unknown → Unknown
//!   5. Destination IP in target allow_ips AND port matches → Allow
//!   6. SNI matches target allow_domains AND port matches  → Allow
//!   7. Otherwise                     → NoMatch
//!
//! Exclude always wins over Allow. Unknown is never treated as Allow.

use super::list::{DomainEntry, IpEntry};
use super::FilterDecision;
use crate::core::{PacketContext, Transport};

/// One target preset (youtube, discord, custom, …).
pub struct TargetPreset {
    pub allow_domains: Vec<DomainEntry>,
    pub allow_ips:     Vec<IpEntry>,
    pub tcp_ports:     Vec<u16>,
    pub udp_ports:     Vec<u16>,
}

impl TargetPreset {
    /// Returns true if the context's destination port matches the preset for its transport.
    pub fn port_matches(&self, ctx: &PacketContext<'_>) -> bool {
        match ctx.transport {
            Transport::Tcp => self.tcp_ports.contains(&ctx.destination_port),
            Transport::Udp => self.udp_ports.contains(&ctx.destination_port),
        }
    }

    /// Returns true if the destination IP is in the allow list AND the port matches.
    pub fn ip_allow(&self, ctx: &PacketContext<'_>) -> bool {
        self.port_matches(ctx)
            && self.allow_ips.iter().any(|e| e.contains(&ctx.destination))
    }

    /// Returns true if the SNI is visible, matches a domain entry AND the port matches.
    pub fn domain_allow(&self, ctx: &PacketContext<'_>) -> bool {
        let Some(sni) = ctx.server_name else { return false; };
        let sni_lower = sni.to_ascii_lowercase();
        self.port_matches(ctx)
            && self.allow_domains.iter().any(|e| e.matches(&sni_lower))
    }
}

pub struct FilterEngine {
    pub exclude_ips:     Vec<IpEntry>,
    pub exclude_domains: Vec<DomainEntry>,
    pub presets:         Vec<TargetPreset>,
}

impl FilterEngine {
    pub fn new(
        exclude_ips: Vec<IpEntry>,
        exclude_domains: Vec<DomainEntry>,
        presets: Vec<TargetPreset>,
    ) -> Self {
        Self { exclude_ips, exclude_domains, presets }
    }
}

impl super::DestinationFilter for FilterEngine {
    fn evaluate(&self, ctx: &PacketContext<'_>) -> FilterDecision {
        // Step 2: exclude by IP.
        if self.exclude_ips.iter().any(|e| e.contains(&ctx.destination)) {
            return FilterDecision::Exclude;
        }

        // Step 3+4: exclude domains / unknown-when-configured.
        if !self.exclude_domains.is_empty() {
            match ctx.server_name {
                Some(sni) => {
                    let sni_lower = sni.to_ascii_lowercase();
                    if self.exclude_domains.iter().any(|e| e.matches(&sni_lower)) {
                        return FilterDecision::Exclude;
                    }
                }
                // Domain exclusions are configured but we can't see the SNI →
                // we cannot guarantee the exclusion, so block modification.
                None => return FilterDecision::Unknown,
            }
        }

        // Steps 5+6: check each enabled preset.
        for preset in &self.presets {
            if preset.ip_allow(ctx) || preset.domain_allow(ctx) {
                return FilterDecision::Allow;
            }
        }

        FilterDecision::NoMatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{InitialMetadata, Transport};
    use super::super::{DestinationFilter, FilterDecision};

    fn make_ctx<'a>(
        dst: &str, port: u16, transport: Transport, sni: Option<&'a str>,
    ) -> PacketContext<'a> {
        PacketContext {
            packet: &[],
            destination: dst.parse().unwrap(),
            destination_port: port,
            transport,
            server_name: sni,
            initial: InitialMetadata::Unknown,
            initial_payload: true,
            filter: FilterDecision::Unknown,
        }
    }

    fn empty_engine() -> FilterEngine {
        FilterEngine::new(vec![], vec![], vec![])
    }

    #[test]
    fn no_presets_gives_no_match() {
        let engine = empty_engine();
        let ctx = make_ctx("1.2.3.4", 443, Transport::Tcp, Some("example.com"));
        assert_eq!(engine.evaluate(&ctx), FilterDecision::NoMatch);
    }

    #[test]
    fn exclude_ip_wins_over_allow() {
        use super::super::list::IpEntry;
        let preset = TargetPreset {
            allow_ips: vec![IpEntry::Single("1.2.3.4".parse().unwrap())],
            allow_domains: vec![],
            tcp_ports: vec![443],
            udp_ports: vec![],
        };
        let engine = FilterEngine::new(
            vec![IpEntry::Single("1.2.3.4".parse().unwrap())],
            vec![],
            vec![preset],
        );
        let ctx = make_ctx("1.2.3.4", 443, Transport::Tcp, None);
        assert_eq!(engine.evaluate(&ctx), FilterDecision::Exclude);
    }

    #[test]
    fn ip_allow_works() {
        use super::super::list::IpEntry;
        let preset = TargetPreset {
            allow_ips: vec![IpEntry::Single("5.5.5.5".parse().unwrap())],
            allow_domains: vec![],
            tcp_ports: vec![443],
            udp_ports: vec![],
        };
        let engine = FilterEngine::new(vec![], vec![], vec![preset]);
        let ctx = make_ctx("5.5.5.5", 443, Transport::Tcp, None);
        assert_eq!(engine.evaluate(&ctx), FilterDecision::Allow);
    }

    #[test]
    fn ip_allow_wrong_port_no_match() {
        use super::super::list::IpEntry;
        let preset = TargetPreset {
            allow_ips: vec![IpEntry::Single("5.5.5.5".parse().unwrap())],
            allow_domains: vec![],
            tcp_ports: vec![443],
            udp_ports: vec![],
        };
        let engine = FilterEngine::new(vec![], vec![], vec![preset]);
        let ctx = make_ctx("5.5.5.5", 80, Transport::Tcp, None);
        assert_eq!(engine.evaluate(&ctx), FilterDecision::NoMatch);
    }

    #[test]
    fn domain_allow_works() {
        use super::super::list::DomainEntry;
        let preset = TargetPreset {
            allow_ips: vec![],
            allow_domains: vec![DomainEntry::Suffix("example.com".into())],
            tcp_ports: vec![443],
            udp_ports: vec![],
        };
        let engine = FilterEngine::new(vec![], vec![], vec![preset]);
        let ctx = make_ctx("1.1.1.1", 443, Transport::Tcp, Some("sub.example.com"));
        assert_eq!(engine.evaluate(&ctx), FilterDecision::Allow);
    }

    #[test]
    fn exclude_domain_wins_over_allow() {
        use super::super::list::{DomainEntry, IpEntry};
        let preset = TargetPreset {
            allow_ips: vec![IpEntry::Single("1.2.3.4".parse().unwrap())],
            allow_domains: vec![DomainEntry::Exact("bad.example.com".into())],
            tcp_ports: vec![443],
            udp_ports: vec![],
        };
        let engine = FilterEngine::new(
            vec![],
            vec![DomainEntry::Exact("bad.example.com".into())],
            vec![preset],
        );
        let ctx = make_ctx("1.2.3.4", 443, Transport::Tcp, Some("bad.example.com"));
        assert_eq!(engine.evaluate(&ctx), FilterDecision::Exclude);
    }

    #[test]
    fn exclude_domains_configured_but_sni_unknown_gives_unknown() {
        use super::super::list::DomainEntry;
        let engine = FilterEngine::new(
            vec![],
            vec![DomainEntry::Exact("bad.example.com".into())],
            vec![],
        );
        // SNI is None → Unknown (cannot verify exclusion)
        let ctx = make_ctx("1.2.3.4", 443, Transport::Tcp, None);
        assert_eq!(engine.evaluate(&ctx), FilterDecision::Unknown);
    }

    #[test]
    fn domain_allow_with_no_sni_is_no_match_not_allow() {
        use super::super::list::DomainEntry;
        let preset = TargetPreset {
            allow_ips: vec![],
            allow_domains: vec![DomainEntry::Exact("example.com".into())],
            tcp_ports: vec![443],
            udp_ports: vec![],
        };
        let engine = FilterEngine::new(vec![], vec![], vec![preset]);
        // no SNI → can't match domain → NoMatch (no exclusions configured, so not Unknown)
        let ctx = make_ctx("1.1.1.1", 443, Transport::Tcp, None);
        assert_eq!(engine.evaluate(&ctx), FilterDecision::NoMatch);
    }
}
