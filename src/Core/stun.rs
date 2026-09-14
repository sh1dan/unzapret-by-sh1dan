//! Safe, bounds-checked STUN (RFC 5389 / RFC 8489) parser.
//! Identifies STUN Binding Requests for NAT traversal (used by Discord Voice)
//! and differentiates them from RTP/SRTP voice media streams.
//! Guarantee: Voice media streams (RTP) are never modified.

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

#[derive(Debug, PartialEq, Eq)]
pub enum StunError {
    Truncated,
    InvalidMagicCookie,
    InvalidType,
    MalformedLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StunHeader {
    pub message_type: u16,
    pub message_length: u16,
    pub transaction_id: [u8; 12],
}

impl StunHeader {
    pub fn is_binding_request(&self) -> bool {
        self.message_type == 0x0001
    }

    pub fn is_binding_response(&self) -> bool {
        self.message_type == 0x0101
    }
}

/// Attempts to parse a UDP payload as a STUN message.
pub fn parse_stun(payload: &[u8]) -> Result<StunHeader, StunError> {
    // STUN header is exactly 20 bytes
    if payload.len() < 20 {
        return Err(StunError::Truncated);
    }

    let message_type = u16::from_be_bytes([payload[0], payload[1]]);
    // RFC 5389: The most significant 2 bits of message type MUST be zeroes (0b00xx_xxxx_xxxx_xxxx)
    if (message_type & 0xC000) != 0 {
        return Err(StunError::InvalidType);
    }

    let message_length = u16::from_be_bytes([payload[2], payload[3]]);
    // RFC 5389: message length does not include the 20-byte header
    // and must be padded to a multiple of 4 bytes
    if (message_length % 4) != 0 {
        return Err(StunError::MalformedLength);
    }
    if 20 + usize::from(message_length) > payload.len() {
        return Err(StunError::Truncated);
    }

    let magic_cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if magic_cookie != STUN_MAGIC_COOKIE {
        return Err(StunError::InvalidMagicCookie);
    }

    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&payload[8..20]);

    Ok(StunHeader {
        message_type,
        message_length,
        transaction_id,
    })
}

/// Detects if a UDP payload is an RTP/SRTP media packet (RFC 3550).
/// RTP packets have Version == 2 in the top 2 bits and DO NOT have the STUN magic cookie.
pub fn is_rtp_media(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }
    let version = payload[0] >> 6;
    if version != 2 {
        return false;
    }
    // STUN packets on the same port share the channel (RFC 7983 demultiplexing).
    // If magic cookie matches STUN_MAGIC_COOKIE, it is STUN, not media.
    if payload.len() >= 8 {
        let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        if cookie == STUN_MAGIC_COOKIE {
            return false;
        }
    }
    true
}

/// Builds a minimal valid STUN Binding Request (for testing).
pub fn build_test_stun_binding_request() -> Vec<u8> {
    let mut pkt = Vec::new();
    // Message Type: 0x0001 (Binding Request)
    pkt.extend_from_slice(&0x0001u16.to_be_bytes());
    // Message Length: 0 (no attributes)
    pkt.extend_from_slice(&0x0000u16.to_be_bytes());
    // Magic Cookie: 0x2112A442
    pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    // Transaction ID: 12 bytes
    pkt.extend_from_slice(&[0x42; 12]);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_stun_binding_request() {
        let pkt = build_test_stun_binding_request();
        let header = parse_stun(&pkt).expect("should parse valid STUN");
        assert!(header.is_binding_request());
        assert_eq!(header.message_length, 0);
        assert_eq!(header.transaction_id, [0x42; 12]);
    }

    #[test]
    fn parse_stun_rejects_invalid_magic_cookie() {
        let mut pkt = build_test_stun_binding_request();
        pkt[4] = 0x00; // corrupt cookie
        assert_eq!(parse_stun(&pkt), Err(StunError::InvalidMagicCookie));
    }

    #[test]
    fn parse_stun_rejects_truncated() {
        let pkt = build_test_stun_binding_request();
        assert_eq!(parse_stun(&pkt[..15]), Err(StunError::Truncated));
    }

    #[test]
    fn rtp_media_identification() {
        // RTP Version 2 packet
        let mut rtp = vec![0u8; 40];
        rtp[0] = 0x80; // Version 2, no padding, no extension, CC 0
        rtp[1] = 0x60; // Payload type 96 (Opus)
        assert!(is_rtp_media(&rtp));

        // STUN packet is NOT media
        let stun = build_test_stun_binding_request();
        assert!(!is_rtp_media(&stun));
    }
}
