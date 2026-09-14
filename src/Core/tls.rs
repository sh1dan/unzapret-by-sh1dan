//! Safe, bounds-checked TLS ClientHello parser for Server Name Indication (SNI).
//! Never panics, never heap allocates domain strings, checks all vector lengths.
//! Conforms to RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3), and RFC 6066 (Server Name Indication).

#[derive(Debug, PartialEq, Eq)]
pub enum TlsError {
    Truncated,
    NotClientHello,
    Malformed,
}

/// Attempts to parse a TLS ClientHello from a TCP payload slice and extract the open SNI hostname.
/// Returns Ok(Some(hostname)) if SNI is present and valid ASCII.
/// Returns Ok(None) if it is a valid ClientHello without SNI (or ECH encrypted).
/// Returns Err(TlsError) if payload is not a valid TLS ClientHello record.
pub fn parse_client_hello(payload: &[u8]) -> Result<Option<&str>, TlsError> {
    // ── 1. TLS Record Header (5 bytes) ───────────────────────────────────────
    // Byte 0: ContentType (22 = Handshake)
    // Byte 1..3: Legacy Version (0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2/1.3)
    // Byte 3..5: Record Length
    if payload.len() < 5 {
        return Err(TlsError::Truncated);
    }
    if payload[0] != 22 {
        return Err(TlsError::NotClientHello);
    }
    let legacy_version = u16::from_be_bytes([payload[1], payload[2]]);
    if !(0x0301..=0x0304).contains(&legacy_version) {
        return Err(TlsError::NotClientHello);
    }
    let record_len = usize::from(u16::from_be_bytes([payload[3], payload[4]]));
    if record_len == 0 {
        return Err(TlsError::Malformed);
    }
    let record_data = &payload[5..std::cmp::min(payload.len(), 5 + record_len)];
    if record_data.len() < 4 {
        return Err(TlsError::Truncated);
    }

    // ── 2. Handshake Header (4 bytes) ────────────────────────────────────────
    // Byte 0: Handshake Type (1 = ClientHello)
    // Byte 1..4: Length (24-bit uint)
    if record_data[0] != 1 {
        return Err(TlsError::NotClientHello);
    }
    let hs_len = (usize::from(record_data[1]) << 16)
        | (usize::from(record_data[2]) << 8)
        | usize::from(record_data[3]);
    let hs_body = &record_data[4..];
    if hs_body.len() < hs_len && payload.len() < 5 + record_len {
        return Err(TlsError::Truncated);
    }

    // ── 3. ClientHello Body ──────────────────────────────────────────────────
    // Client Version (2 bytes) + Random (32 bytes) = 34 bytes minimum
    let mut cursor = 0;
    if hs_body.len() < 34 {
        return Err(TlsError::Truncated);
    }
    cursor += 34; // skip version and random

    // Session ID: 1-byte length + vector
    if cursor >= hs_body.len() { return Err(TlsError::Truncated); }
    let session_id_len = usize::from(hs_body[cursor]);
    cursor += 1;
    if cursor + session_id_len > hs_body.len() { return Err(TlsError::Truncated); }
    cursor += session_id_len;

    // Cipher Suites: 2-byte length + vector
    if cursor + 2 > hs_body.len() { return Err(TlsError::Truncated); }
    let cipher_suites_len = usize::from(u16::from_be_bytes([hs_body[cursor], hs_body[cursor + 1]]));
    cursor += 2;
    if cursor + cipher_suites_len > hs_body.len() { return Err(TlsError::Truncated); }
    cursor += cipher_suites_len;

    // Compression Methods: 1-byte length + vector
    if cursor >= hs_body.len() { return Err(TlsError::Truncated); }
    let compression_len = usize::from(hs_body[cursor]);
    cursor += 1;
    if cursor + compression_len > hs_body.len() { return Err(TlsError::Truncated); }
    cursor += compression_len;

    // Extensions: 2-byte length + vector
    if cursor == hs_body.len() {
        return Ok(None); // No extensions present
    }
    if cursor + 2 > hs_body.len() { return Err(TlsError::Truncated); }
    let extensions_len = usize::from(u16::from_be_bytes([hs_body[cursor], hs_body[cursor + 1]]));
    cursor += 2;
    let extensions_end = cursor + extensions_len;
    if extensions_end > hs_body.len() { return Err(TlsError::Truncated); }

    // ── 4. Iterate Extensions to find SNI (type 0x0000) ───────────────────────
    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([hs_body[cursor], hs_body[cursor + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([hs_body[cursor + 2], hs_body[cursor + 3]]));
        cursor += 4;
        if cursor + ext_len > extensions_end {
            return Err(TlsError::Truncated);
        }
        let ext_data = &hs_body[cursor..cursor + ext_len];
        cursor += ext_len;

        if ext_type == 0x0000 {
            // SNI extension structure:
            // Server Name List Length (2 bytes)
            if ext_data.len() < 2 { return Err(TlsError::Malformed); }
            let list_len = usize::from(u16::from_be_bytes([ext_data[0], ext_data[1]]));
            if list_len + 2 > ext_data.len() { return Err(TlsError::Malformed); }
            let mut list_cursor = 2;
            while list_cursor + 3 <= 2 + list_len {
                let name_type = ext_data[list_cursor];
                let name_len = usize::from(u16::from_be_bytes([
                    ext_data[list_cursor + 1],
                    ext_data[list_cursor + 2],
                ]));
                list_cursor += 3;
                if list_cursor + name_len > 2 + list_len {
                    return Err(TlsError::Malformed);
                }
                if name_type == 0 {
                    // HostName (ASCII)
                    let hostname_bytes = &ext_data[list_cursor..list_cursor + name_len];
                    if let Ok(hostname) = std::str::from_utf8(hostname_bytes) {
                        return Ok(Some(hostname));
                    }
                }
                list_cursor += name_len;
            }
        }
    }

    Ok(None)
}

/// Constructs a minimal valid TLS ClientHello with the given SNI hostname (for testing).
pub fn build_test_client_hello(sni: &str) -> Vec<u8> {
    let mut extensions = Vec::new();
    // SNI extension
    let sni_bytes = sni.as_bytes();
    let name_entry_len = 1 + 2 + sni_bytes.len(); // type(1) + len(2) + name
    let list_len = name_entry_len;
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes());
    sni_ext.push(0); // HostName type
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    // Add SNI extension header (type 0, len)
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    let mut hs_body = Vec::new();
    hs_body.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2
    hs_body.extend_from_slice(&[0xaa; 32]); // Random
    hs_body.push(0); // Session ID len = 0
    hs_body.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites len = 2
    hs_body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
    hs_body.push(1); // Compression methods len = 1
    hs_body.push(0); // null compression
    hs_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hs_body.extend_from_slice(&extensions);

    let mut record = Vec::new();
    record.push(22); // Handshake
    record.extend_from_slice(&0x0301u16.to_be_bytes()); // Legacy version
    let hs_total_len = 4 + hs_body.len();
    record.extend_from_slice(&(hs_total_len as u16).to_be_bytes());

    // Handshake header
    record.push(1); // ClientHello
    record.push((hs_body.len() >> 16) as u8);
    record.push((hs_body.len() >> 8) as u8);
    record.push(hs_body.len() as u8);
    record.extend_from_slice(&hs_body);

    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_client_hello_sni() {
        let ch = build_test_client_hello("twitch.tv");
        let result = parse_client_hello(&ch).expect("should parse successfully");
        assert_eq!(result, Some("twitch.tv"));
    }

    #[test]
    fn parse_truncated_client_hello() {
        let ch = build_test_client_hello("telegram.org");
        assert_eq!(parse_client_hello(&ch[..10]), Err(TlsError::Truncated));
        assert_eq!(parse_client_hello(&ch[..40]), Err(TlsError::Truncated));
    }

    #[test]
    fn parse_non_tls_returns_not_client_hello() {
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_client_hello(http), Err(TlsError::NotClientHello));
    }
}
