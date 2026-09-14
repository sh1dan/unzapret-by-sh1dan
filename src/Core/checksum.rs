//! RFC 1071 One's Complement Internet Checksum implementation.
//! Bounds-checked, no panics, no raw pointers, strictly safe Rust.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Calculates the 16-bit one's complement sum of the given byte slice.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += u32::from(word);
    }
    let remainder = chunks.remainder();
    if let Some(&last_byte) = remainder.first() {
        let word = u16::from_be_bytes([last_byte, 0]);
        sum += u32::from(word);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

/// Computes the standard IPv4 header checksum over `header[..header_len]`.
/// Expects the checksum field (bytes 10..12) to be zeroed before computation.
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    debug_assert!(header.len() >= 20);
    internet_checksum(header)
}

/// Accumulates a 32-bit sum for one's complement addition.
fn fold_sum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Computes the TCP checksum over IPv4 pseudo-header, TCP header, and payload.
/// `tcp_segment` contains `tcp_header + tcp_payload` with the TCP checksum field zeroed.
pub fn tcp_checksum_ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    tcp_segment: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    // IPv4 Pseudo-header:
    // Source IP (4 bytes)
    for chunk in src.octets().chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    // Destination IP (4 bytes)
    for chunk in dst.octets().chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    // Zero (1 byte) + Protocol TCP (6) (1 byte)
    sum += 6u32;
    // TCP length (2 bytes)
    sum += tcp_segment.len() as u32;

    // Add TCP segment bytes
    let mut chunks = tcp_segment.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    let remainder = chunks.remainder();
    if let Some(&last_byte) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last_byte, 0]));
    }

    fold_sum(sum)
}

/// Computes the TCP checksum over IPv6 pseudo-header, TCP header, and payload.
/// `tcp_segment` contains `tcp_header + tcp_payload` with the TCP checksum field zeroed.
pub fn tcp_checksum_ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    tcp_segment: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    // IPv6 Pseudo-header:
    // Source IP (16 bytes)
    for chunk in src.octets().chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    // Destination IP (16 bytes)
    for chunk in dst.octets().chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    // Upper-Layer Packet Length (4 bytes)
    let len = tcp_segment.len() as u32;
    sum += len >> 16;
    sum += len & 0xffff;
    // Next Header TCP (6) (4 bytes: 3 zero bytes + 6)
    sum += 6u32;

    // Add TCP segment bytes
    let mut chunks = tcp_segment.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    let remainder = chunks.remainder();
    if let Some(&last_byte) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last_byte, 0]));
    }

    fold_sum(sum)
}

/// Convenience wrapper for either IPv4 or IPv6 TCP checksum calculation.
pub fn tcp_checksum(
    src: IpAddr,
    dst: IpAddr,
    tcp_segment: &[u8],
) -> u16 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => tcp_checksum_ipv4(s, d, tcp_segment),
        (IpAddr::V6(s), IpAddr::V6(d)) => tcp_checksum_ipv6(s, d, tcp_segment),
        _ => 0,
    }
}

/// Computes the UDP checksum over IPv4 pseudo-header, UDP header, and payload.
/// `udp_segment` contains `udp_header + payload` with checksum field zeroed.
pub fn udp_checksum_ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    udp_segment: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    for chunk in dst.octets().chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    // Protocol UDP (17)
    sum += 17u32;
    // UDP length
    sum += udp_segment.len() as u32;

    let mut chunks = udp_segment.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    let remainder = chunks.remainder();
    if let Some(&last_byte) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last_byte, 0]));
    }

    let csum = fold_sum(sum);
    if csum == 0 { 0xffff } else { csum }
}

/// Computes the UDP checksum over IPv6 pseudo-header, UDP header, and payload.
/// `udp_segment` contains `udp_header + payload` with checksum field zeroed.
pub fn udp_checksum_ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    udp_segment: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.octets().chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    for chunk in dst.octets().chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    let len = udp_segment.len() as u32;
    sum += len >> 16;
    sum += len & 0xffff;
    // Next Header UDP (17)
    sum += 17u32;

    let mut chunks = udp_segment.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    let remainder = chunks.remainder();
    if let Some(&last_byte) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last_byte, 0]));
    }

    let csum = fold_sum(sum);
    if csum == 0 { 0xffff } else { csum }
}

/// Convenience wrapper for either IPv4 or IPv6 UDP checksum calculation.
pub fn udp_checksum(
    src: IpAddr,
    dst: IpAddr,
    udp_segment: &[u8],
) -> u16 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => udp_checksum_ipv4(s, d, udp_segment),
        (IpAddr::V6(s), IpAddr::V6(d)) => udp_checksum_ipv6(s, d, udp_segment),
        _ => 0,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example_vector() {
        // RFC 1071 Section 3 example:
        // Byte 0..8: 00 01 f2 03 f4 f5 f6 f7
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        // 0001 + f203 = f204
        // f204 + f4f5 = 1e6f9 -> e6fa
        // e6fa + f6f7 = 1ddf1 -> ddf2
        // ~ddf2 = 220d
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn odd_length_checksum() {
        let data = [0x00, 0x01, 0xf2];
        // 0001 + f200 = f201
        // ~f201 = 0dfe
        assert_eq!(internet_checksum(&data), 0x0dfe);
    }

    #[test]
    fn ipv4_header_checksum_vector() {
        // Standard IPv4 20-byte header with known valid checksum
        let mut header = [
            0x45, 0x00, 0x00, 0x3c, // IPv4, IHL 5, Total Len 60
            0x1c, 0x46, 0x40, 0x00, // ID 0x1c46, Don't fragment
            0x40, 0x06, 0x00, 0x00, // TTL 64, TCP (6), Checksum 0x0000 (pre-calculation)
            0xac, 0x10, 0x0a, 0x63, // Src: 172.16.10.99
            0xac, 0x10, 0x0a, 0x0c, // Dst: 172.16.10.12
        ];
        let csum = ipv4_header_checksum(&header);
        assert_eq!(csum, 0xb1e6);

        // Verification: when computed over header including valid checksum, result is 0
        header[10..12].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(internet_checksum(&header), 0x0000);
    }

    #[test]
    fn tcp_checksum_ipv4_vector() {
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let mut tcp_seg = vec![
            0x04, 0x00, 0x00, 0x50, // src port 1024, dst port 80
            0x00, 0x00, 0x00, 0x01, // seq 1
            0x00, 0x00, 0x00, 0x00, // ack 0
            0x50, 0x02, 0x20, 0x00, // offset 5, SYN, window 8192
            0x00, 0x00, 0x00, 0x00, // checksum 0, urgent 0
        ];
        let csum = tcp_checksum_ipv4(src, dst, &tcp_seg);
        assert_ne!(csum, 0);

        // Put checksum in place
        tcp_seg[16..18].copy_from_slice(&csum.to_be_bytes());
        // Verify via pseudo-header
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(tcp_seg.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&tcp_seg);
        assert_eq!(internet_checksum(&pseudo), 0x0000);
    }

    #[test]
    fn udp_checksum_ipv4_vector() {
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let mut udp_seg = vec![
            0xc3, 0x50, 0x00, 0x35, // src port 50000, dst port 53
            0x00, 0x0c, 0x00, 0x00, // length 12, checksum 0
            0xde, 0xad, 0xbe, 0xef, // payload 4 bytes
        ];
        let csum = udp_checksum_ipv4(src, dst, &udp_seg);
        assert_ne!(csum, 0);

        udp_seg[6..8].copy_from_slice(&csum.to_be_bytes());
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&(udp_seg.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&udp_seg);
        assert_eq!(internet_checksum(&pseudo), 0x0000);
    }
}

