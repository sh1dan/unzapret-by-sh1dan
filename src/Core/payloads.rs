//! Embedded fake payloads for DPI desynchronization (Discord Voice UDP, QUIC, etc.)
//! These binary payloads mirror proven bypass profiles from Zapret (Flowseal/bol-van).

pub static DISCORD_VOICE_UDP_FAKE: &[u8] = include_bytes!("../../assets/active_discord_udp.bin");
pub static GOOGLE_QUIC_UDP_FAKE: &[u8] = include_bytes!("../../assets/quic_initial_google.bin");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_are_embedded_and_non_empty() {
        assert_eq!(DISCORD_VOICE_UDP_FAKE.len(), 1200);
        assert_eq!(GOOGLE_QUIC_UDP_FAKE.len(), 1200);
    }
}
