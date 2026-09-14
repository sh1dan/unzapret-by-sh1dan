//! Safe, bounds-checked QUIC Initial packet parser (RFC 9000).
//! Inspects Long Header packets to identify QUIC Initial handshake packets
//! and extract the negotiated QUIC version without decrypting payload.

#[derive(Debug, PartialEq, Eq)]
pub enum QuicError {
    Truncated,
    NotLongHeader,
    NotInitial,
    Malformed,
}

#[derive(Debug, PartialEq, Eq)]
pub struct QuicInitialHeader {
    pub version: u32,
    pub dcid_len: usize,
    pub scid_len: usize,
}

/// Parses a variable-length integer (varint) according to RFC 9000 Section 16.
pub fn parse_varint(bytes: &[u8]) -> Result<(u64, usize), QuicError> {
    let first = *bytes.first().ok_or(QuicError::Truncated)?;
    let prefix = first >> 6;
    let len = 1 << prefix;
    if bytes.len() < len {
        return Err(QuicError::Truncated);
    }
    let value = match len {
        1 => u64::from(first & 0x3f),
        2 => u64::from(u16::from_be_bytes([first & 0x3f, bytes[1]])),
        4 => u64::from(u32::from_be_bytes([first & 0x3f, bytes[1], bytes[2], bytes[3]])),
        8 => u64::from_be_bytes([
            first & 0x3f, bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        _ => unreachable!(),
    };
    Ok((value, len))
}

/// Inspects a UDP packet payload to detect and parse a QUIC Initial packet.
pub fn parse_quic_initial(payload: &[u8]) -> Result<QuicInitialHeader, QuicError> {
    // Minimum Long Header: 1 (flags) + 4 (version) + 1 (DCIL) + 1 (SCIL) = 7 bytes
    if payload.len() < 7 {
        return Err(QuicError::Truncated);
    }
    let first_byte = payload[0];
    // Header Form (bit 7): 1 = Long Header
    if (first_byte & 0x80) == 0 {
        return Err(QuicError::NotLongHeader);
    }
    // Fixed bit (bit 6): MUST be 1 in RFC 9000
    if (first_byte & 0x40) == 0 {
        return Err(QuicError::NotLongHeader);
    }
    // Long Packet Type (bits 4-5):
    // 0x00 = Initial
    let packet_type = (first_byte >> 4) & 0x03;
    if packet_type != 0x00 {
        return Err(QuicError::NotInitial);
    }

    // Version (4 bytes, big endian)
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    if version == 0 {
        // Version Negotiation packet, not Initial
        return Err(QuicError::NotInitial);
    }

    let mut cursor = 5;
    // Destination Connection ID Length (1 byte)
    let dcid_len = usize::from(payload[cursor]);
    cursor += 1;
    if dcid_len > 20 || cursor + dcid_len > payload.len() {
        return Err(QuicError::Malformed);
    }
    cursor += dcid_len;

    // Source Connection ID Length (1 byte)
    if cursor >= payload.len() {
        return Err(QuicError::Truncated);
    }
    let scid_len = usize::from(payload[cursor]);
    cursor += 1;
    if scid_len > 20 || cursor + scid_len > payload.len() {
        return Err(QuicError::Malformed);
    }
    cursor += scid_len;

    // Token Length (varint)
    let (_token_len, _varint_len) = parse_varint(&payload[cursor..])?;

    Ok(QuicInitialHeader {
        version,
        dcid_len,
        scid_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_quic_v1_initial() {
        let mut pkt = Vec::new();
        // Byte 0: 1 (Long) | 1 (Fixed) | 00 (Initial) | 00 (Reserved/Packet Number length) = 0xc0
        pkt.push(0xc0);
        // Version: 1 (0x00000001)
        pkt.extend_from_slice(&1u32.to_be_bytes());
        // DCID len: 8, DCID: 8 bytes
        pkt.push(8);
        pkt.extend_from_slice(&[0x11; 8]);
        // SCID len: 4, SCID: 4 bytes
        pkt.push(4);
        pkt.extend_from_slice(&[0x22; 4]);
        // Token len: 0 (varint 0 = 0x00)
        pkt.push(0);
        // Length (varint) + payload
        pkt.push(0x40); // 2-byte varint
        pkt.push(0x20);

        let parsed = parse_quic_initial(&pkt).expect("should parse valid quic initial");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.dcid_len, 8);
        assert_eq!(parsed.scid_len, 4);
    }

    #[test]
    fn parse_short_header_rejected() {
        // Short header has bit 7 == 0
        let pkt = [0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        assert_eq!(parse_quic_initial(&pkt), Err(QuicError::NotLongHeader));
    }
}
