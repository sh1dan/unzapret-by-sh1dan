//! TXT list parser: domains and IP/CIDR entries, one per line.
//! '#' starts a comment; blank lines are skipped.
//! All parsing is bounds-checked; any syntax error returns ListError.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A single parsed domain entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainEntry {
    /// Exact hostname match (e.g. `example.com`).
    Exact(String),
    /// Matches the apex and all subdomains strictly by label boundary
    /// (e.g. `.example.com` → `example.com` and `sub.example.com`,
    ///  but NOT `notexample.com`).
    Suffix(String),
}

/// A single parsed IP/CIDR entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpEntry {
    Single(IpAddr),
    CidrV4 { addr: Ipv4Addr, prefix: u8 },
    CidrV6 { addr: Ipv6Addr, prefix: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListError {
    /// 1-based line number of the offending entry.
    pub line: usize,
    pub message: &'static str,
}

impl ListError {
    const fn new(line: usize, message: &'static str) -> Self { Self { line, message } }
}

impl std::fmt::Display for ListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}
impl std::error::Error for ListError {}

/// Parse a domain TXT list. Returns all entries or the first error.
pub fn parse_domains(text: &str) -> Result<Vec<DomainEntry>, ListError> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_num = idx + 1;
        let entry = strip_comment(raw).trim();
        if entry.is_empty() { continue; }
        out.push(parse_domain_entry(entry, line_num)?);
    }
    Ok(out)
}

/// Parse an IP/CIDR TXT list. Returns all entries or the first error.
pub fn parse_ips(text: &str) -> Result<Vec<IpEntry>, ListError> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_num = idx + 1;
        let entry = strip_comment(raw).trim();
        if entry.is_empty() { continue; }
        out.push(parse_ip_entry(entry, line_num)?);
    }
    Ok(out)
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(before, _)| before)
}

fn parse_domain_entry(entry: &str, line: usize) -> Result<DomainEntry, ListError> {
    if entry.len() > 253 {
        return Err(ListError::new(line, "domain name too long (max 253 chars)"));
    }
    if entry.starts_with('.') {
        // Suffix entry: strip leading dot, then validate the rest as a hostname.
        let host = &entry[1..];
        if host.is_empty() {
            return Err(ListError::new(line, "suffix entry has no hostname after dot"));
        }
        validate_hostname(host, line)?;
        Ok(DomainEntry::Suffix(normalise_domain(host)))
    } else {
        validate_hostname(entry, line)?;
        Ok(DomainEntry::Exact(normalise_domain(entry)))
    }
}

/// ASCII-only, case-insensitive, trailing dot stripped.
fn normalise_domain(host: &str) -> String {
    let h = host.strip_suffix('.').unwrap_or(host);
    h.to_ascii_lowercase()
}

fn validate_hostname(host: &str, line: usize) -> Result<(), ListError> {
    if host.is_empty() {
        return Err(ListError::new(line, "empty hostname"));
    }
    // Must be ASCII; Unicode must be pre-encoded as punycode.
    if !host.is_ascii() {
        return Err(ListError::new(line, "non-ASCII hostname: use punycode encoding"));
    }
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() {
            return Err(ListError::new(line, "empty label in hostname"));
        }
        if label.len() > 63 {
            return Err(ListError::new(line, "label exceeds 63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ListError::new(line, "label starts or ends with hyphen"));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ListError::new(line, "invalid character in label (use a-z, 0-9, hyphen)"));
        }
    }
    Ok(())
}

fn parse_ip_entry(entry: &str, line: usize) -> Result<IpEntry, ListError> {
    let invalid = || ListError::new(line, "invalid IP address or CIDR notation");
    if let Some((addr_str, prefix_str)) = entry.split_once('/') {
        // CIDR
        let prefix: u8 = prefix_str.parse().map_err(|_| invalid())?;
        if let Ok(v4) = addr_str.parse::<Ipv4Addr>() {
            if prefix > 32 { return Err(ListError::new(line, "IPv4 prefix length exceeds 32")); }
            // Host bits must be zero.
            let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
            if u32::from(v4) & !mask != 0 {
                return Err(ListError::new(line, "IPv4 CIDR has non-zero host bits"));
            }
            return Ok(IpEntry::CidrV4 { addr: v4, prefix });
        }
        if let Ok(v6) = addr_str.parse::<Ipv6Addr>() {
            if prefix > 128 { return Err(ListError::new(line, "IPv6 prefix length exceeds 128")); }
            let addr_bits = u128::from(v6);
            let mask = if prefix == 0 { 0u128 } else { !0u128 << (128 - prefix) };
            if addr_bits & !mask != 0 {
                return Err(ListError::new(line, "IPv6 CIDR has non-zero host bits"));
            }
            return Ok(IpEntry::CidrV6 { addr: v6, prefix });
        }
        Err(invalid())
    } else {
        // Single address
        entry.parse::<IpAddr>().map(IpEntry::Single).map_err(|_| invalid())
    }
}

impl IpEntry {
    /// Returns true if `addr` is covered by this entry.
    pub fn contains(&self, addr: &IpAddr) -> bool {
        match (self, addr) {
            (IpEntry::Single(a), b) => a == b,
            (IpEntry::CidrV4 { addr, prefix }, IpAddr::V4(b)) => {
                let mask = if *prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
                u32::from(*addr) & mask == u32::from(*b) & mask
            }
            (IpEntry::CidrV6 { addr, prefix }, IpAddr::V6(b)) => {
                let mask = if *prefix == 0 { 0u128 } else { !0u128 << (128 - prefix) };
                u128::from(*addr) & mask == u128::from(*b) & mask
            }
            _ => false,
        }
    }
}

impl DomainEntry {
    /// Case-insensitive match against a lowercase SNI string.
    pub fn matches(&self, sni: &str) -> bool {
        match self {
            DomainEntry::Exact(host) => sni == host.as_str(),
            DomainEntry::Suffix(apex) => {
                // sni == apex  OR  sni ends with ".<apex>" (strict label boundary)
                sni == apex.as_str()
                    || sni.strip_suffix(apex.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_matches_itself() {
        let e = DomainEntry::Exact("example.com".into());
        assert!(e.matches("example.com"));
        assert!(!e.matches("sub.example.com"));
        assert!(!e.matches("notexample.com"));
    }

    #[test]
    fn suffix_domain_matches_apex_and_subs() {
        let e = DomainEntry::Suffix("example.com".into());
        assert!(e.matches("example.com"));
        assert!(e.matches("sub.example.com"));
        assert!(e.matches("a.b.example.com"));
        assert!(!e.matches("notexample.com"));
        assert!(!e.matches("example.com.evil.org"));
    }

    #[test]
    fn cidr_v4_contains() {
        let e = IpEntry::CidrV4 { addr: "192.168.0.0".parse().unwrap(), prefix: 24 };
        assert!(e.contains(&"192.168.0.1".parse().unwrap()));
        assert!(e.contains(&"192.168.0.255".parse().unwrap()));
        assert!(!e.contains(&"192.168.1.0".parse().unwrap()));
    }

    #[test]
    fn cidr_v6_contains() {
        let e = IpEntry::CidrV6 { addr: "2001:db8::".parse().unwrap(), prefix: 32 };
        assert!(e.contains(&"2001:db8::1".parse().unwrap()));
        assert!(!e.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn parse_domains_parses_comment_and_blank() {
        let text = "# comment\n\nexample.com\n.suffix.net\n";
        let entries = parse_domains(text).unwrap();
        assert_eq!(entries, vec![
            DomainEntry::Exact("example.com".into()),
            DomainEntry::Suffix("suffix.net".into()),
        ]);
    }

    #[test]
    fn parse_domains_rejects_non_ascii() {
        assert!(parse_domains("пример.com\n").is_err());
    }

    #[test]
    fn parse_domains_rejects_empty_label() {
        assert!(parse_domains("a..b.com\n").is_err());
    }

    #[test]
    fn parse_domains_rejects_leading_hyphen() {
        assert!(parse_domains("-bad.com\n").is_err());
    }

    #[test]
    fn parse_ips_single_v4_and_cidr() {
        let text = "1.2.3.4\n10.0.0.0/8\n";
        let entries = parse_ips(text).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[0], IpEntry::Single(IpAddr::V4(_))));
        assert!(matches!(entries[1], IpEntry::CidrV4 { prefix: 8, .. }));
    }

    #[test]
    fn parse_ips_rejects_non_zero_host_bits() {
        assert!(parse_ips("10.0.0.1/8\n").is_err());
    }

    #[test]
    fn parse_ips_rejects_prefix_too_large() {
        assert!(parse_ips("10.0.0.0/33\n").is_err());
    }

    #[test]
    fn parse_ips_rejects_garbage() {
        assert!(parse_ips("not_an_ip\n").is_err());
    }
}
