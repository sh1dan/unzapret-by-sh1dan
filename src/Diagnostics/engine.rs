//! System Diagnostics Engine (`dpi-bypass diagnose`).
//! Performs read-only inspections conforming to docs/architecture.md:
//! - Admin privileges
//! - WinDivert driver files
//! - DNS A/AAAA & dual-stack
//! - HTTPS endpoints (YouTube, Discord)
//! - QUIC / HTTP/3 (honest Unsupported / NotRun)
//! - Discord Voice / STUN prerequisites
//! - Proxy / VPN environment detection
//! - Competing packet-filter driver detection
//! - Windows SCM service state

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use super::{CheckResult, CheckStatus, Diagnostics, PLANNED_CHECKS};

pub struct DefaultDiagnostics;

impl Diagnostics for DefaultDiagnostics {
    fn run(&self) -> Vec<CheckResult> {
        vec![
            check_admin_privileges(),
            check_windivert_availability(),
            check_dns_dual_stack(),
            check_youtube_https(),
            check_discord_https(),
            check_quic_support(),
            check_discord_voice_prerequisites(),
            check_proxy_vpn_settings(),
            check_packet_filter_drivers(),
            check_windows_service(),
        ]
    }
}

fn check_admin_privileges() -> CheckResult {
    let name = PLANNED_CHECKS[0];
    match windivert_adapter::require_administrator() {
        Ok(()) => CheckResult {
            name,
            status: CheckStatus::Ok,
            message: "Process is elevated with administrator privileges".into(),
        },
        Err(e) => CheckResult {
            name,
            status: CheckStatus::Failed,
            message: format!("Process is unprivileged ({e}). Admin required for capture/service."),
        },
    }
}

fn check_windivert_availability() -> CheckResult {
    let name = PLANNED_CHECKS[1];
    match windivert_adapter::driver_files() {
        Ok((dll, sys)) => CheckResult {
            name,
            status: CheckStatus::Ok,
            message: format!(
                "Driver files verified ({}, {})",
                dll.display(),
                sys.display()
            ),
        },
        Err(e) => CheckResult {
            name,
            status: CheckStatus::Failed,
            message: format!("WinDivert files missing or inaccessible: {e}"),
        },
    }
}

fn check_dns_dual_stack() -> CheckResult {
    let name = PLANNED_CHECKS[2];
    let host = "cloudflare.com:443";
    match host.to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<SocketAddr> = addrs.collect();
            let has_v4 = addrs.iter().any(|a| a.is_ipv4());
            let has_v6 = addrs.iter().any(|a| a.is_ipv6());

            if has_v4 && has_v6 {
                CheckResult {
                    name,
                    status: CheckStatus::Ok,
                    message: format!(
                        "Dual-stack operational ({} addresses: IPv4 + IPv6)",
                        addrs.len()
                    ),
                }
            } else if has_v4 {
                CheckResult {
                    name,
                    status: CheckStatus::Ok,
                    message: format!(
                        "DNS operational (IPv4 available, {} addrs; no IPv6 detected)",
                        addrs.len()
                    ),
                }
            } else if has_v6 {
                CheckResult {
                    name,
                    status: CheckStatus::Ok,
                    message: format!(
                        "DNS operational (IPv6 available, {} addrs; no IPv4 detected)",
                        addrs.len()
                    ),
                }
            } else {
                CheckResult {
                    name,
                    status: CheckStatus::Failed,
                    message: "DNS resolver returned 0 addresses".into(),
                }
            }
        }
        Err(e) => CheckResult {
            name,
            status: CheckStatus::Failed,
            message: format!("DNS resolution error: {e}"),
        },
    }
}

fn check_youtube_https() -> CheckResult {
    let name = PLANNED_CHECKS[3];
    let target = crate::core::tester::TestTarget {
        name: "YouTube",
        endpoint: "www.youtube.com:443",
        sni: "www.youtube.com",
        port: 443,
        protocol: "HTTPS",
    };
    let (status, latency) =
        crate::core::tester::probe_live_tls(&target, Duration::from_millis(3000));
    match status {
        crate::core::tester::ProbeStatus::Ok(ver) => CheckResult {
            name,
            status: CheckStatus::NotRun,
            message: format!("TLS record header received ({ver}, {latency} ms); certificate, complete handshake and HTTPS response NOT verified"),
        },
        s => CheckResult {
            name,
            status: CheckStatus::Failed,
            message: format!("{s} ({latency} ms)"),
        },
    }
}

fn check_discord_https() -> CheckResult {
    let name = PLANNED_CHECKS[4];
    let target = crate::core::tester::TestTarget {
        name: "Discord",
        endpoint: "discord.com:443",
        sni: "discord.com",
        port: 443,
        protocol: "HTTPS",
    };
    let (status, latency) =
        crate::core::tester::probe_live_tls(&target, Duration::from_millis(3000));
    match status {
        crate::core::tester::ProbeStatus::Ok(ver) => CheckResult {
            name,
            status: CheckStatus::NotRun,
            message: format!("TLS record header received ({ver}, {latency} ms); certificate, complete handshake and HTTPS response NOT verified"),
        },
        s => CheckResult {
            name,
            status: CheckStatus::Failed,
            message: format!("{s} ({latency} ms)"),
        },
    }
}

fn check_quic_support() -> CheckResult {
    let name = PLANNED_CHECKS[5];
    // Honest reporting: without active QUIC bypass driver configuration,
    // report Unsupported / NotRun rather than a fabricated Ok.
    CheckResult {
        name,
        status: CheckStatus::Unsupported,
        message: "HTTP/3 / QUIC bypass engine disabled by safe default profile".into(),
    }
}

fn check_discord_voice_prerequisites() -> CheckResult {
    let name = PLANNED_CHECKS[6];
    // Verify local UDP socket creation and binding
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(_sock) => CheckResult {
            name,
            status: CheckStatus::NotRun,
            message: "Local UDP bind succeeded. Remote Discord voice connectivity was NOT tested; no UDP probe was sent.".into(),
        },
        Err(e) => CheckResult {
            name,
            status: CheckStatus::Failed,
            message: format!("Cannot bind local UDP socket: {e}"),
        },
    }
}

fn check_proxy_vpn_settings() -> CheckResult {
    let name = PLANNED_CHECKS[7];
    let mut detected = Vec::new();
    for var in &[
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                detected.push((*var).to_owned());
            }
        }
    }

    if detected.is_empty() {
        CheckResult {
            name,
            status: CheckStatus::Ok,
            message: "No proxy environment variables set; Windows proxy/VPN state was not checked"
                .into(),
        }
    } else {
        CheckResult {
            name,
            status: CheckStatus::Ok,
            message: format!(
                "Proxy variables set (values redacted): {}",
                detected.join(", ")
            ),
        }
    }
}

fn check_packet_filter_drivers() -> CheckResult {
    let name = PLANNED_CHECKS[8];
    // Read-only inspection: check if another WinDivert process or service is running
    // Checks for typical competing services (e.g. goodbyedpi, zapret) in SCM
    let competing = ["goodbyedpi", "zapret", "byedpi"];
    let mut active = Vec::new();
    for svc in &competing {
        if let Ok(state) = windivert_adapter::scm_query_status(svc) {
            if state == windivert_adapter::ScmState::Running {
                active.push(*svc);
            }
        }
    }

    if active.is_empty() {
        CheckResult {
            name,
            status: CheckStatus::Ok,
            message: "No conflicting third-party filter services running".into(),
        }
    } else {
        CheckResult {
            name,
            status: CheckStatus::Failed,
            message: format!(
                "Conflicting filter service(s) running: {}",
                active.join(", ")
            ),
        }
    }
}

fn check_windows_service() -> CheckResult {
    let name = PLANNED_CHECKS[9];
    match windivert_adapter::scm_query_status(crate::service::SERVICE_NAME) {
        Ok(state) => CheckResult {
            name,
            status: CheckStatus::Ok,
            message: format!("LocalDpiBypass service state: {state}"),
        },
        Err(e) => CheckResult {
            name,
            status: CheckStatus::Failed,
            message: format!("Failed to query service state: {e}"),
        },
    }
}

/// Formats diagnostic results into a standardized console table.
pub fn format_diagnostics_report(results: &[CheckResult]) -> String {
    let mut out = String::new();
    out.push_str("System Diagnostics Report (Read-Only):\n");
    out.push_str(&format!("{}\n", "-".repeat(78)));
    for r in results {
        let tag = match r.status {
            CheckStatus::Ok => "[PASS]",
            CheckStatus::Failed => "[FAIL]",
            CheckStatus::Unsupported => "[INFO]",
            CheckStatus::NotRun => "[SKIP]",
        };
        out.push_str(&format!("{:<7} {:<32} {}\n", tag, r.name, r.message));
    }
    out.push_str(&format!("{}\n", "-".repeat(78)));
    out
}

/// Runs the complete diagnostic suite and returns formatted report and exit code.
pub fn run_diagnostics() -> (u8, String) {
    let engine = DefaultDiagnostics;
    let results = engine.run();
    let text = format_diagnostics_report(&results);

    // Log the diagnostic run to app.log
    let _ = super::logger::append_log(
        super::logger::LogLevel::Info,
        "DIAGNOSTIC",
        &format!("Completed {} diagnostic checks", results.len()),
    );

    let has_fail = results.iter().any(|r| r.status == CheckStatus::Failed);
    let code = if has_fail { 1 } else { 0 };
    (code, text)
}
