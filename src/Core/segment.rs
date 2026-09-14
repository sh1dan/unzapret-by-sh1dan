//! TCP packet segmenter (Split-TCP evasion primitive).
//! Splits an initial TCP packet into two contiguous wire-valid TCP packets.
//! Strict invariants:
//!   - seg1.payload + seg2.payload == original.payload
//!   - seg1.seq == original.seq
//!   - seg2.seq == original.seq + seg1.payload.len()
//!   - IPv4/IPv6 total lengths and checksums are recomputed and valid.

use std::net::IpAddr;
use super::checksum::{ipv4_header_checksum, tcp_checksum, udp_checksum};
use super::parser::{parse, TransportMetadata};

#[derive(Debug, PartialEq, Eq)]
pub enum SegmentError {
    MalformedPacket,
    UnsupportedProtocol,
    NotTcp,
    PayloadTooSmall,
    InvalidOffset,
}

/// Splits a complete IPv4 or IPv6 TCP packet at `payload_offset` relative to TCP payload.
/// Both returned packets are independently valid on the wire.
pub fn split_tcp_packet(
    original_packet: &[u8],
    payload_offset: usize,
) -> Result<(Vec<u8>, Vec<u8>), SegmentError> {
    let meta = parse(original_packet).map_err(|e| match e {
        super::parser::ParseError::Malformed => SegmentError::MalformedPacket,
        super::parser::ParseError::Unsupported => SegmentError::UnsupportedProtocol,
    })?;

    let (src_ip, dst_ip, ip_hdr_len) = (meta.source, meta.destination, meta.header_length);
    let (tcp_data_offset, orig_flags) = match meta.transport {
        TransportMetadata::Tcp { data_offset, flags, .. } => (usize::from(data_offset) * 4, flags),
        _ => return Err(SegmentError::NotTcp),
    };

    let tcp_hdr_start = ip_hdr_len;
    let tcp_hdr_end = tcp_hdr_start + tcp_data_offset;
    if tcp_hdr_end > original_packet.len() {
        return Err(SegmentError::MalformedPacket);
    }

    let payload = &original_packet[tcp_hdr_end..];
    if payload.len() < 2 {
        return Err(SegmentError::PayloadTooSmall);
    }
    if payload_offset == 0 || payload_offset >= payload.len() {
        return Err(SegmentError::InvalidOffset);
    }

    let orig_seq = u32::from_be_bytes([
        original_packet[tcp_hdr_start + 4],
        original_packet[tcp_hdr_start + 5],
        original_packet[tcp_hdr_start + 6],
        original_packet[tcp_hdr_start + 7],
    ]);

    let payload1 = &payload[..payload_offset];
    let payload2 = &payload[payload_offset..];

    // ── Build Segment 1 ──────────────────────────────────────────────────────
    let seg1 = build_tcp_segment(
        meta.version,
        src_ip,
        dst_ip,
        &original_packet[..ip_hdr_len],
        &original_packet[tcp_hdr_start..tcp_hdr_end],
        orig_seq,
        orig_flags & !0x0008, // Clear PSH on segment 1, push happens on final segment
        payload1,
        0, // identification delta
    );

    // ── Build Segment 2 ──────────────────────────────────────────────────────
    let seg2_seq = orig_seq.wrapping_add(payload_offset as u32);
    let seg2 = build_tcp_segment(
        meta.version,
        src_ip,
        dst_ip,
        &original_packet[..ip_hdr_len],
        &original_packet[tcp_hdr_start..tcp_hdr_end],
        seg2_seq,
        orig_flags, // Keep original flags (including PSH if present) on segment 2
        payload2,
        1, // identification delta for IPv4
    );

    Ok((seg1, seg2))
}

fn build_tcp_segment(
    version: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    orig_ip_hdr: &[u8],
    orig_tcp_hdr: &[u8],
    seq: u32,
    flags: u16,
    payload: &[u8],
    id_delta: u16,
) -> Vec<u8> {
    let ip_hdr_len = orig_ip_hdr.len();
    let tcp_hdr_len = orig_tcp_hdr.len();
    let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

    let mut packet = vec![0u8; total_len];
    packet[..ip_hdr_len].copy_from_slice(orig_ip_hdr);
    packet[ip_hdr_len..ip_hdr_len + tcp_hdr_len].copy_from_slice(orig_tcp_hdr);
    packet[ip_hdr_len + tcp_hdr_len..].copy_from_slice(payload);

    // Update IP header
    match version {
        4 => {
            // Update Total Length (bytes 2..4)
            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            // Advance Identification (bytes 4..6)
            let orig_id = u16::from_be_bytes([packet[4], packet[5]]);
            packet[4..6].copy_from_slice(&orig_id.wrapping_add(id_delta).to_be_bytes());
            // Zero Checksum (bytes 10..12) and recompute
            packet[10..12].copy_from_slice(&[0, 0]);
            let ip_csum = ipv4_header_checksum(&packet[..ip_hdr_len]);
            packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        }
        6 => {
            // Update Payload Length (bytes 4..6, excludes 40-byte IPv6 fixed header)
            let ipv6_payload_len = (tcp_hdr_len + payload.len()) as u16;
            packet[4..6].copy_from_slice(&ipv6_payload_len.to_be_bytes());
        }
        _ => unreachable!(),
    }

    // Update TCP header
    let tcp_start = ip_hdr_len;
    // Sequence number (bytes 4..8 of TCP header)
    packet[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
    // Flags (byte 12 low bit + byte 13)
    packet[tcp_start + 12] = (packet[tcp_start + 12] & 0xfe) | ((flags >> 8) as u8 & 1);
    packet[tcp_start + 13] = flags as u8;

    // Recompute TCP Checksum (bytes 16..18 of TCP header)
    packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&[0, 0]);
    let tcp_csum = tcp_checksum(src_ip, dst_ip, &packet[tcp_start..]);
    packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());

    packet
}

/// Constructs a valid fake UDP packet with identical IP/UDP source/dest endpoints
/// but replaced fake payload and updated lengths and checksums.
pub fn create_fake_udp_packet(
    original_packet: &[u8],
    fake_payload: &[u8],
) -> Result<Vec<u8>, SegmentError> {
    let meta = parse(original_packet).map_err(|e| match e {
        super::parser::ParseError::Malformed => SegmentError::MalformedPacket,
        super::parser::ParseError::Unsupported => SegmentError::UnsupportedProtocol,
    })?;

    if !matches!(meta.transport, TransportMetadata::Udp { .. }) {
        return Err(SegmentError::UnsupportedProtocol);
    }

    let (src_ip, dst_ip, ip_hdr_len) = (meta.source, meta.destination, meta.header_length);
    let udp_hdr_start = ip_hdr_len;
    let udp_hdr_end = udp_hdr_start + 8;
    if udp_hdr_end > original_packet.len() {
        return Err(SegmentError::MalformedPacket);
    }

    let udp_len = 8 + fake_payload.len();
    let total_len = ip_hdr_len + udp_len;
    let mut packet = vec![0u8; total_len];

    // Copy original IP header
    packet[..ip_hdr_len].copy_from_slice(&original_packet[..ip_hdr_len]);
    // Copy original UDP ports (bytes 0..4 of UDP header: src_port, dst_port)
    packet[udp_hdr_start..udp_hdr_start + 4].copy_from_slice(&original_packet[udp_hdr_start..udp_hdr_start + 4]);
    // Set new UDP length (bytes 4..6 of UDP header)
    packet[udp_hdr_start + 4..udp_hdr_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // Zero UDP checksum placeholder (bytes 6..8 of UDP header)
    packet[udp_hdr_start + 6..udp_hdr_start + 8].copy_from_slice(&[0, 0]);
    // Copy fake payload
    packet[udp_hdr_end..].copy_from_slice(fake_payload);

    // Update IP header lengths and checksums
    match meta.version {
        4 => {
            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            packet[10..12].copy_from_slice(&[0, 0]);
            let ip_csum = ipv4_header_checksum(&packet[..ip_hdr_len]);
            packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        }
        6 => {
            packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        }
        _ => return Err(SegmentError::UnsupportedProtocol),
    }

    // Recompute UDP checksum
    let udp_csum = udp_checksum(src_ip, dst_ip, &packet[udp_hdr_start..]);
    let csum_bytes = if udp_csum == 0 { [0xff, 0xff] } else { udp_csum.to_be_bytes() };
    packet[udp_hdr_start + 6..udp_hdr_start + 8].copy_from_slice(&csum_bytes);

    Ok(packet)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_test_ipv4_tcp_packet(payload_data: &[u8]) -> Vec<u8> {
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let ip_hdr_len = 20;
        let tcp_hdr_len = 20;
        let total_len = ip_hdr_len + tcp_hdr_len + payload_data.len();

        let mut pkt = vec![0u8; total_len];
        // IPv4 header
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 6;  // Protocol TCP
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        let ip_csum = ipv4_header_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // TCP header
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());   // dst port
        pkt[24..28].copy_from_slice(&100_000u32.to_be_bytes()); // seq
        pkt[28..32].copy_from_slice(&50_000u32.to_be_bytes());  // ack
        pkt[32] = 0x50; // offset 5 (20 bytes)
        pkt[33] = 0x18; // ACK + PSH
        pkt[34..36].copy_from_slice(&8192u16.to_be_bytes()); // window

        // Copy payload
        pkt[40..].copy_from_slice(payload_data);

        // TCP checksum
        let tcp_csum = tcp_checksum(src.into(), dst.into(), &pkt[20..]);
        pkt[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

        pkt
    }

    #[test]
    fn split_tcp_exact_bytes_and_sequence_invariant() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let orig = make_test_ipv4_tcp_packet(payload);
        let split_offset = 2;

        let (seg1, seg2) = split_tcp_packet(&orig, split_offset).expect("split should succeed");

        // Parse segment 1
        let meta1 = parse(&seg1).expect("seg1 valid");
        let payload1 = &seg1[meta1.header_length + 20..];
        assert_eq!(payload1, &payload[..split_offset]);

        // Parse segment 2
        let meta2 = parse(&seg2).expect("seg2 valid");
        let payload2 = &seg2[meta2.header_length + 20..];
        assert_eq!(payload2, &payload[split_offset..]);

        // Invariant: concatenated payloads are byte-for-byte identical to original
        assert_eq!([payload1, payload2].concat(), payload);

        // Invariant: sequence numbers
        let seq1 = u32::from_be_bytes([seg1[meta1.header_length + 4], seg1[meta1.header_length + 5],
                                       seg1[meta1.header_length + 6], seg1[meta1.header_length + 7]]);
        let seq2 = u32::from_be_bytes([seg2[meta2.header_length + 4], seg2[meta2.header_length + 5],
                                       seg2[meta2.header_length + 6], seg2[meta2.header_length + 7]]);
        assert_eq!(seq1, 100_000);
        assert_eq!(seq2, 100_000 + split_offset as u32);
    }

    #[test]
    fn create_fake_udp_packet_preserves_endpoints_and_updates_checksum() {
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(162, 159, 138, 232);
        let orig_payload = b"real-stun-packet";
        let fake_payload = b"fake-udp-payload-1200-bytes";

        let total_len = 20 + 8 + orig_payload.len();
        let mut orig_pkt = vec![0u8; total_len];
        orig_pkt[0] = 0x45;
        orig_pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        orig_pkt[8] = 64;
        orig_pkt[9] = 17; // UDP
        orig_pkt[12..16].copy_from_slice(&src.octets());
        orig_pkt[16..20].copy_from_slice(&dst.octets());
        let ip_csum = ipv4_header_checksum(&orig_pkt[..20]);
        orig_pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        orig_pkt[20..22].copy_from_slice(&50000u16.to_be_bytes());
        orig_pkt[22..24].copy_from_slice(&50001u16.to_be_bytes());
        orig_pkt[24..26].copy_from_slice(&((8 + orig_payload.len()) as u16).to_be_bytes());
        orig_pkt[28..].copy_from_slice(orig_payload);

        let fake_pkt = create_fake_udp_packet(&orig_pkt, fake_payload).expect("should succeed");
        assert_eq!(fake_pkt.len(), 20 + 8 + fake_payload.len());
        // Verify payload replaced
        assert_eq!(&fake_pkt[28..], fake_payload);
        // Verify endpoints preserved
        assert_eq!(&fake_pkt[12..16], &src.octets());
        assert_eq!(&fake_pkt[16..20], &dst.octets());
        assert_eq!(&fake_pkt[20..22], &50000u16.to_be_bytes());
        assert_eq!(&fake_pkt[22..24], &50001u16.to_be_bytes());
        // Verify valid IP checksum
        assert_eq!(crate::core::checksum::internet_checksum(&fake_pkt[..20]), 0x0000);
        // Verify valid UDP checksum
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&((8 + fake_payload.len()) as u16).to_be_bytes());
        pseudo.extend_from_slice(&fake_pkt[20..]);
        assert_eq!(crate::core::checksum::internet_checksum(&pseudo), 0x0000);
    }
}


