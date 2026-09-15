//! Inspect only; never serialize, rewrite, reassemble or checksum packets.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Malformed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportMetadata {
    Tcp {
        source_port: u16,
        destination_port: u16,
        data_offset: u8,
        flags: u16,
    },
    Udp {
        source_port: u16,
        destination_port: u16,
        length: u16,
    },
}

/// Not Debug: endpoints must not accidentally enter diagnostic logs.
pub struct Metadata {
    pub version: u8,
    pub header_length: usize,
    pub total_length: usize,
    pub payload_length: usize,
    pub protocol: u8,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub transport: TransportMetadata,
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

pub fn parse(bytes: &[u8]) -> Result<Metadata, ParseError> {
    let version = bytes.first().ok_or(ParseError::Malformed)? >> 4;
    let (header_length, total_length, protocol, source, destination) = match version {
        4 => {
            if bytes.len() < 20 {
                return Err(ParseError::Malformed);
            }
            let ihl = usize::from(bytes[0] & 15) * 4;
            let total = usize::from(be16(bytes, 2));
            if ihl < 20 || ihl > bytes.len() || total < ihl || total != bytes.len() {
                return Err(ParseError::Malformed);
            }
            if be16(bytes, 6) & 0x3fff != 0 {
                return Err(ParseError::Unsupported);
            }
            let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
            let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
            (ihl, total, bytes[9], source.into(), destination.into())
        }
        6 => {
            if bytes.len() < 40 {
                return Err(ParseError::Malformed);
            }
            let payload = usize::from(be16(bytes, 4));
            if payload == 0 && bytes.len() > 40 {
                return Err(ParseError::Unsupported);
            }
            let total = 40 + payload;
            if total != bytes.len() {
                return Err(ParseError::Malformed);
            }
            let mut source = [0u8; 16];
            let mut destination = [0u8; 16];
            source.copy_from_slice(&bytes[8..24]);
            destination.copy_from_slice(&bytes[24..40]);
            (
                40,
                total,
                bytes[6],
                Ipv6Addr::from(source).into(),
                Ipv6Addr::from(destination).into(),
            )
        }
        _ => return Err(ParseError::Malformed),
    };
    let payload = &bytes[header_length..total_length];
    let transport = match protocol {
        6 => {
            if payload.len() < 20 {
                return Err(ParseError::Malformed);
            }
            let offset = payload[12] >> 4;
            if offset < 5 || usize::from(offset) * 4 > payload.len() {
                return Err(ParseError::Malformed);
            }
            TransportMetadata::Tcp {
                source_port: be16(payload, 0),
                destination_port: be16(payload, 2),
                data_offset: offset,
                flags: (u16::from(payload[12] & 1) << 8) | u16::from(payload[13]),
            }
        }
        17 => {
            if payload.len() < 8 {
                return Err(ParseError::Malformed);
            }
            let length = be16(payload, 4);
            if length < 8 || usize::from(length) != payload.len() {
                return Err(ParseError::Malformed);
            }
            TransportMetadata::Udp {
                source_port: be16(payload, 0),
                destination_port: be16(payload, 2),
                length,
            }
        }
        _ => return Err(ParseError::Unsupported),
    };
    Ok(Metadata {
        version,
        header_length,
        total_length,
        payload_length: total_length - header_length,
        protocol,
        source,
        destination,
        transport,
    })
}
