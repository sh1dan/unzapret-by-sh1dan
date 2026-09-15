//! Sequential Strategy Tester (`dpi-bypass test`).
//! Sequentially evaluates bypass strategies (pass-through, split-tcp) against
//! target endpoints (YouTube, Discord, Twitch, Telegram).
//! Strictly respects safety requirements:
//! - No competing capture handles
//! - Sequential execution with fresh connections and timeouts
//! - In-memory evaluation; never permanently modifies `config/default.toml`
//! - Honest attribution: reports `INCONCLUSIVE` if strategy was not applied.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct TestTarget {
    pub name: &'static str,
    pub endpoint: &'static str,
    pub sni: &'static str,
    pub port: u16,
    pub protocol: &'static str,
}

pub const DEFAULT_TARGETS: &[TestTarget] = &[
    TestTarget {
        name: "YouTube",
        endpoint: "www.youtube.com:443",
        sni: "www.youtube.com",
        port: 443,
        protocol: "HTTPS",
    },
    TestTarget {
        name: "Discord",
        endpoint: "discord.com:443",
        sni: "discord.com",
        port: 443,
        protocol: "HTTPS",
    },
    TestTarget {
        name: "Twitch",
        endpoint: "twitch.tv:443",
        sni: "twitch.tv",
        port: 443,
        protocol: "HTTPS",
    },
    TestTarget {
        name: "Telegram",
        endpoint: "t.me:443",
        sni: "t.me",
        port: 443,
        protocol: "HTTPS",
    },
];

pub const DEFAULT_STRATEGIES: &[&str] = &["pass-through", "split-tcp"];

pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(3500);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeStatus {
    Ok(String),
    Blocked(String),
    Timeout,
    ConnectionRefused,
    DnsError(String),
    Error(String),
}

impl std::fmt::Display for ProbeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeStatus::Ok(s) => write!(f, "OK ({s})"),
            ProbeStatus::Blocked(s) => write!(f, "BLOCKED/{s}"),
            ProbeStatus::Timeout => write!(f, "TIMEOUT"),
            ProbeStatus::ConnectionRefused => write!(f, "REFUSED"),
            ProbeStatus::DnsError(s) => write!(f, "DNS_ERR: {s}"),
            ProbeStatus::Error(s) => write!(f, "ERR: {s}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestVerdict {
    Success,
    Fail,
    Inconclusive,
}

impl std::fmt::Display for TestVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestVerdict::Success => write!(f, "SUCCESS"),
            TestVerdict::Fail => write!(f, "FAIL"),
            TestVerdict::Inconclusive => write!(f, "INCONCLUSIVE"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub target: String,
    pub strategy: String,
    pub status: ProbeStatus,
    pub latency_ms: u64,
    pub applied: bool,
    pub result: TestVerdict,
}

/// Determines the test verdict based on probe status, application confirmation, and strategy.
/// Inconclusive if:
/// - A non-pass-through strategy was not confirmed applied (e.g. driver inactive)
/// - Network/DNS resolution error prevented reaching the target
pub fn determine_verdict(status: &ProbeStatus, applied: bool, strategy: &str) -> TestVerdict {
    match status {
        ProbeStatus::Ok(_) => {
            if strategy == "pass-through" || applied {
                TestVerdict::Success
            } else {
                TestVerdict::Inconclusive
            }
        }
        ProbeStatus::Blocked(_) | ProbeStatus::Timeout | ProbeStatus::ConnectionRefused => {
            TestVerdict::Fail
        }
        ProbeStatus::DnsError(_) | ProbeStatus::Error(_) => TestVerdict::Inconclusive,
    }
}

/// Formats a series of test results into a standardized console table.
pub fn format_results_table(results: &[ProbeResult]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<24} {:<15} {:<20} {:<10} {}\n",
        "Target", "Strategy", "Status", "Latency", "Result"
    ));
    out.push_str(&format!("{}\n", "-".repeat(78)));
    for r in results {
        let lat = format!("{} ms", r.latency_ms);
        let status_str = format!("{}", r.status);
        out.push_str(&format!(
            "{:<24} {:<15} {:<20} {:<10} {}\n",
            r.target, r.strategy, status_str, lat, r.result
        ));
    }
    out
}

/// Runs probe evaluation with a pluggable prober function for deterministic testing.
pub fn run_test_suite_with_prober<F>(
    targets: &[TestTarget],
    strategies: &[&str],
    mut prober: F,
) -> Vec<ProbeResult>
where
    F: FnMut(&TestTarget, &str) -> (ProbeStatus, u64, bool),
{
    let mut results = Vec::new();
    for strategy in strategies {
        for target in targets {
            let (status, latency_ms, applied) = prober(target, strategy);
            let verdict = determine_verdict(&status, applied, strategy);
            results.push(ProbeResult {
                target: target.endpoint.to_string(),
                strategy: strategy.to_string(),
                status,
                latency_ms,
                applied,
                result: verdict,
            });
        }
    }
    results
}

/// Performs a live TLS ClientHello probe to the specified target.
pub fn probe_live_tls(target: &TestTarget, timeout: Duration) -> (ProbeStatus, u64) {
    use std::io::{Read, Write};

    let start = Instant::now();
    let addrs: Vec<SocketAddr> = match target.endpoint.to_socket_addrs() {
        Ok(it) => it.collect(),
        Err(e) => return (ProbeStatus::DnsError(e.to_string()), 0),
    };

    if addrs.is_empty() {
        return (ProbeStatus::DnsError("no addresses resolved".into()), 0);
    }

    let stream = match TcpStream::connect_timeout(&addrs[0], timeout) {
        Ok(s) => s,
        Err(e) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let status = match e.kind() {
                std::io::ErrorKind::TimedOut => ProbeStatus::Timeout,
                std::io::ErrorKind::ConnectionRefused => ProbeStatus::ConnectionRefused,
                std::io::ErrorKind::ConnectionReset => ProbeStatus::Blocked("RST".into()),
                _ => ProbeStatus::Error(e.to_string()),
            };
            return (status, elapsed);
        }
    };

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let client_hello = crate::core::tls::build_test_client_hello(target.sni);
    let mut stream = stream;
    if let Err(e) = stream.write_all(&client_hello) {
        let elapsed = start.elapsed().as_millis() as u64;
        let status = match e.kind() {
            std::io::ErrorKind::ConnectionReset => ProbeStatus::Blocked("RST".into()),
            std::io::ErrorKind::TimedOut => ProbeStatus::Timeout,
            _ => ProbeStatus::Error(e.to_string()),
        };
        return (status, elapsed);
    }

    // Read initial response header (5 bytes of TLS Record Header)
    let mut resp = [0u8; 5];
    match stream.read_exact(&mut resp) {
        Ok(()) => {
            let elapsed = start.elapsed().as_millis() as u64;
            if resp[0] == 22 {
                let version = match (resp[1], resp[2]) {
                    (3, 3) => "TLS 1.2/1.3",
                    (3, 1) => "TLS 1.0",
                    _ => "TLS",
                };
                (ProbeStatus::Ok(version.to_string()), elapsed)
            } else {
                (
                    ProbeStatus::Blocked(format!("byte 0x{:02x}", resp[0])),
                    elapsed,
                )
            }
        }
        Err(e) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let status = match e.kind() {
                std::io::ErrorKind::ConnectionReset => ProbeStatus::Blocked("RST".into()),
                std::io::ErrorKind::UnexpectedEof => ProbeStatus::Blocked("EOF".into()),
                std::io::ErrorKind::TimedOut => ProbeStatus::Timeout,
                _ => ProbeStatus::Error(e.to_string()),
            };
            (status, elapsed)
        }
    }
}

/// Runs the strategy tester in mock mode for deterministic CI/contracts verification.
pub fn run_mock_tester() -> String {
    let results =
        run_test_suite_with_prober(DEFAULT_TARGETS, DEFAULT_STRATEGIES, |target, strategy| {
            match strategy {
                "pass-through" => (ProbeStatus::Blocked("RST".into()), 45, true),
                "split-tcp" => {
                    let latency = match target.name {
                        "YouTube" => 38,
                        "Discord" => 41,
                        "Twitch" => 29,
                        "Telegram" => 55,
                        _ => 50,
                    };
                    (ProbeStatus::Ok("TLS 1.3".into()), latency, true)
                }
                _ => (ProbeStatus::Error("unknown strategy".into()), 0, false),
            }
        });
    format_results_table(&results)
}

/// Runs the sequential strategy tester.
/// If `mock` is true, produces mock output without network I/O.
pub fn execute_tester(mock: bool) -> (u8, String) {
    if mock {
        let table = run_mock_tester();
        let mut msg = String::from("Running sequential strategy tester (mock mode):\n\n");
        msg.push_str(&table);
        msg.push_str("\nAll simulated tests completed successfully.\n");
        return (0, msg);
    }

    // No strategy engine is started here. Report protocol reachability only,
    // always INCONCLUSIVE: a partial TLS response is not validated HTTPS.
    let results =
        run_test_suite_with_prober(DEFAULT_TARGETS, &["connectivity-only"], |target, _| {
            let (status, latency) = probe_live_tls(target, DEFAULT_PROBE_TIMEOUT);
            (status, latency, false)
        });
    let mut results = results;
    for result in &mut results {
        result.result = TestVerdict::Inconclusive;
    }
    let mut output = String::from(
        "Connectivity probes only: NO strategies are started or compared.\n\
         TLS response header only; certificates/HTTPS/voice/QUIC are NOT verified.\n\
         A running capture or VPN may affect these probes.\n\n",
    );
    output.push_str(&format_results_table(&results));
    output.push_str("\nAutomatic strategy selection is unavailable. Configuration unchanged.\n");
    (2, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_attribution_rules() {
        // pass-through succeeds on OK
        assert_eq!(
            determine_verdict(&ProbeStatus::Ok("TLS 1.3".into()), true, "pass-through"),
            TestVerdict::Success
        );
        // split-tcp succeeds on OK when applied
        assert_eq!(
            determine_verdict(&ProbeStatus::Ok("TLS 1.3".into()), true, "split-tcp"),
            TestVerdict::Success
        );
        // split-tcp is INCONCLUSIVE on OK when NOT applied
        assert_eq!(
            determine_verdict(&ProbeStatus::Ok("TLS 1.3".into()), false, "split-tcp"),
            TestVerdict::Inconclusive
        );
        // Blocked / RST is FAIL
        assert_eq!(
            determine_verdict(&ProbeStatus::Blocked("RST".into()), true, "pass-through"),
            TestVerdict::Fail
        );
        assert_eq!(
            determine_verdict(&ProbeStatus::Blocked("RST".into()), true, "split-tcp"),
            TestVerdict::Fail
        );
        // Timeout is FAIL
        assert_eq!(
            determine_verdict(&ProbeStatus::Timeout, true, "split-tcp"),
            TestVerdict::Fail
        );
        // DNS error is INCONCLUSIVE
        assert_eq!(
            determine_verdict(
                &ProbeStatus::DnsError("NXDOMAIN".into()),
                false,
                "split-tcp"
            ),
            TestVerdict::Inconclusive
        );
    }

    #[test]
    fn format_results_table_contains_all_targets_and_strategies() {
        let mock_table = run_mock_tester();
        assert!(mock_table.contains("www.youtube.com:443"));
        assert!(mock_table.contains("discord.com:443"));
        assert!(mock_table.contains("twitch.tv:443"));
        assert!(mock_table.contains("t.me:443"));
        assert!(mock_table.contains("pass-through"));
        assert!(mock_table.contains("split-tcp"));
        assert!(mock_table.contains("SUCCESS"));
        assert!(mock_table.contains("FAIL"));
    }

    #[test]
    fn execute_tester_mock_returns_zero_exit_code() {
        let (code, text) = execute_tester(true);
        assert_eq!(code, 0);
        assert!(text.contains("Target"));
        assert!(text.contains("Strategy"));
        assert!(text.contains("SUCCESS"));
    }
}
