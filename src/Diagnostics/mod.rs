pub mod engine;
pub mod logger;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Failed,
    Unsupported,
    NotRun,
}

pub struct CheckResult {
    pub name: &'static str,
    pub status: CheckStatus,
    /// Human-readable, sanitized message; never include packet data.
    pub message: String,
}

pub trait Diagnostics {
    /// Network probes are allowed only after an explicit test/diagnose command.
    fn run(&self) -> Vec<CheckResult>;
}

pub const PLANNED_CHECKS: &[&str] = &[
    "Administrator privileges",
    "WinDivert availability",
    "DNS / IPv4 / IPv6",
    "YouTube HTTPS",
    "Discord HTTPS",
    "QUIC",
    "Discord voice prerequisites",
    "Proxy / VPN settings",
    "Packet-filter drivers",
    "Windows service",
];

pub fn run_diagnostics() -> (u8, String) {
    engine::run_diagnostics()
}

pub fn show_logs() -> (u8, String) {
    match logger::read_recent_logs(50) {
        Ok(lines) => (0, lines.join("\n")),
        Err(e) => (1, format!("Error reading log file: {e}")),
    }
}
