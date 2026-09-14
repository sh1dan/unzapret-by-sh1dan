use std::{collections::BTreeSet, io::Read, net::IpAddr};
use crate::capture::{CaptureError, ErrorKind};

pub const EXAMPLE: &str = include_str!("../../config/phase2.toml");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phase2Config {
    pub enabled: bool,
    pub destination_ips: Vec<IpAddr>,
    pub tcp_ports: Vec<u16>,
    pub udp_ports: Vec<u16>,
}

fn invalid() -> CaptureError { CaptureError::new(ErrorKind::InvalidConfiguration, None) }

impl Phase2Config {
    pub fn load() -> Result<(Self, String), CaptureError> {
        let root = windivert_adapter::application_dir()?;
        let path = windivert_adapter::validated_file(&root, "config/phase2.toml", ErrorKind::InvalidConfiguration)?;
        let file = std::fs::File::open(path).map_err(|e| CaptureError::from_io(ErrorKind::InvalidConfiguration, &e))?;
        let mut text = String::new();
        file.take(16385).read_to_string(&mut text)
            .map_err(|e| CaptureError::from_io(ErrorKind::InvalidConfiguration, &e))?;
        let config = Self::parse(&text)?;
        Ok((config, text))
    }

    pub fn parse(text: &str) -> Result<Self, CaptureError> {
        if text.len() > 16384 { return Err(invalid()); }
        let value: toml::Value = text.parse().map_err(|_| invalid())?;
        let root = value.as_table().ok_or_else(invalid)?;
        if root.len() != 1 { return Err(invalid()); }
        let table = root.get("phase2_capture").and_then(toml::Value::as_table).ok_or_else(invalid)?;
        if table.len() != 4 { return Err(invalid()); }
        let enabled = table.get("enabled").and_then(toml::Value::as_bool).ok_or_else(invalid)?;
        let ips = table.get("destination_ips").and_then(toml::Value::as_array).ok_or_else(invalid)?;
        if ips.len() > 32 { return Err(invalid()); }
        let destination_ips = ips.iter().map(|v| {
            v.as_str().ok_or_else(invalid)?.parse::<IpAddr>().map_err(|_| invalid())
        }).collect::<Result<Vec<_>, _>>()?;
        let ports = |key: &str| -> Result<Vec<u16>, CaptureError> {
            let values = table.get(key).and_then(toml::Value::as_array).ok_or_else(invalid)?;
            if values.len() > 32 { return Err(invalid()); }
            values.iter().map(|v| {
                let n = v.as_integer().ok_or_else(invalid)?;
                u16::try_from(n).ok().filter(|p| *p != 0).ok_or_else(invalid)
            }).collect()
        };
        let config = Self { enabled, destination_ips, tcp_ports: ports("tcp_ports")?, udp_ports: ports("udp_ports")? };
        config.validate_fields()?;
        Ok(config)
    }

    fn validate_fields(&self) -> Result<(), CaptureError> {
        if self.destination_ips.len() > 32 || self.tcp_ports.len() > 32 || self.udp_ports.len() > 32
            || self.tcp_ports.contains(&0) || self.udp_ports.contains(&0) {
            return Err(invalid());
        }
        for ip in &self.destination_ips {
            let unsuitable = ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()
                || match ip {
                    IpAddr::V4(v4) => v4.is_broadcast() || v4.is_link_local(),
                    IpAddr::V6(v6) => v6.to_ipv4().is_some() || (v6.segments()[0] & 0xffc0 == 0xfe80),
                };
            if unsuitable { return Err(invalid()); }
        }
        Ok(())
    }

    pub fn filter(&self) -> Result<String, CaptureError> {
        self.validate_fields()?;
        if !self.enabled || self.destination_ips.is_empty() || (self.tcp_ports.is_empty() && self.udp_ports.is_empty()) {
            return Err(invalid());
        }
        let ips: BTreeSet<_> = self.destination_ips.iter().map(|ip| match ip {
            IpAddr::V4(_) => format!("(ip and ip.DstAddr == {ip})"),
            IpAddr::V6(_) => format!("(ipv6 and ipv6.DstAddr == {ip})"),
        }).collect();
        let mut transport = Vec::new();
        for (protocol, ports) in [("tcp", &self.tcp_ports), ("udp", &self.udp_ports)] {
            let ports: BTreeSet<_> = ports.iter().map(|p| format!("{protocol}.DstPort == {p}")).collect();
            if !ports.is_empty() { transport.push(format!("({protocol} and ({}))", ports.into_iter().collect::<Vec<_>>().join(" or "))); }
        }
        Ok(format!("outbound and !loopback and !impostor and ({}) and ({})",
            ips.into_iter().collect::<Vec<_>>().join(" or "), transport.join(" or ")))
    }
}
