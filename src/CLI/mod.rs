pub const HELP: &str = "Local DPI Bypass — Phase 9 (Read-Only Diagnostics & Sanitized Logging)
Implemented: start [--dry-run] | status | strategies | config show | test [--mock]
             service install | remove | status | start | stop | restart
             diagnose | logs | help
Reserved (Phase 10): restart | use <strategy>
Reserved commands return exit code 2 without side effects.
Administrator privileges and WinDivert/WinDivert64.sys are required for start and service.";

pub struct Reply { pub code: u8, pub text: String }

/// Pure dispatch: no filesystem, network, registry or SCM access for read-only commands.
/// `start` is the one command that opens captures and requires administrator privileges.
pub fn dispatch(args: &[&str]) -> Reply {
    let (code, text) = match args {
        [] | ["help"] | ["--help"] | ["-h"] => (0, HELP.to_owned()),
        ["status"] => (0, "Phase: 9\nEngine: Read-only diagnostics & sanitized logging enabled\nService: not queried (use 'service status')\nStrategy: pass-through / split-tcp\nConfiguration: not loaded (use start or service start to run)\nPacket counters: unavailable until started".into()),
        ["strategies"] => (0, "pass-through: active — byte-exact reinject, no modification\nsplit-tcp: active — initial TCP payload segmentation\nsplit-tls: planned\nreorder / decoy / quic / stun: design candidates, disabled".into()),
        ["config", "show"] => (0, format!("# Built-in example, NOT loaded runtime configuration\n{}", crate::core::config::EXAMPLE_TOML)),
        ["start"] => run_engine(false),
        ["start", "--dry-run"] => run_engine(true),
        ["test"] => crate::core::tester::execute_tester(false),
        ["test", "--mock"] => crate::core::tester::execute_tester(true),
        ["service", action] => crate::service::dispatch_service_command(action),
        ["diagnose"] => crate::diagnostics::run_diagnostics(),
        ["logs"] => crate::diagnostics::show_logs(),
        ["stop"] => (2, "stop is not implemented in foreground mode. Send Ctrl+C to the running start process, or use 'service stop'.".into()),
        ["restart"] | ["use", _] =>
            (2, "Not implemented. No system changes or network probes performed.".into()),
        _ => (2, format!("Unknown command or arguments.\n{HELP}")),
    };
    Reply { code, text }
}

fn run_engine(dry_run: bool) -> (u8, String) {
    use crate::core::{RunMode, PacketEngine as _, pipeline::PassThroughEngine};
    use crate::core::phase2_config::Phase2Config;
    use crate::core::config_loader::load_config;
    use crate::capture::windivert::WinDivertCapture;

    // ── Load and validate full config/default.toml + TXT lists ──────────────
    let app_dir = match windivert_adapter::application_dir() {
        Ok(d) => d,
        Err(e) => return (1, format!("Cannot determine application directory: {e}")),
    };
    let loaded = match load_config(&app_dir) {
        Ok(c) => c,
        Err(e) => return (1, format!("Configuration error: {e}")),
    };

    // CLI --dry-run flag overrides config; config dry_run=true always wins.
    let effective_dry_run = dry_run || loaded.dry_run;
    let mode = if effective_dry_run { RunMode::DryRun } else { RunMode::Active };
    let mode_label = if effective_dry_run { "dry-run (sniff)" } else { "active (capture+reinject)" };

    // ── Load Phase 2 capture config (validation & fallback) ────────────────
    let p2_config = Phase2Config::load().map(|(c, _)| c).ok();

    // Use dynamic WinDivert filter based on all active presets (or fallback to p2_config)
    let dynamic_filter = loaded.filter_engine.build_windivert_filter();
    let capture = match WinDivertCapture::open_filter(&dynamic_filter, mode) {
        Ok(c) => c,
        Err(_) => {
            // Fallback to phase2.toml if dynamic open fails
            if let Some(ref p2) = p2_config {
                match WinDivertCapture::open(p2, mode) {
                    Ok(c) => c,
                    Err(e) => return (1, format!("Capture open failed: {e}")),
                }
            } else {
                return (1, "Capture open failed: unable to initialize WinDivert driver".into());
            }
        }
    };

    let mut stop_handler = match windivert_adapter::ConsoleStop::install() {
        Ok(h) => h,
        Err(e) => return (1, format!("Ctrl+C handler install failed: {e}")),
    };

    eprintln!("unzapret-by-sh1dan engine started.");
    eprintln!("  Mode:     {mode_label}");
    eprintln!("  Strategy: {}", loaded.strategy);
    eprintln!("  Filter:   Active presets (YouTube, Discord, Voice/STUN, Twitch, Telegram)");
    eprintln!("  Max flows: {}, idle {}s, initial pkts: {}",
        loaded.max_flows, loaded.flow_idle_seconds, loaded.max_packets_per_flow);
    eprintln!("Press Ctrl+C to stop.");

    let strategy_impl: Box<dyn crate::strategies::Strategy> = match loaded.strategy.as_str() {
        "pass-through" => Box::new(crate::strategies::PassThrough),
        "split-tcp-only" => Box::new(crate::strategies::SplitTcp::default()),
        _ => Box::new(crate::strategies::AutoBypass::default()),
    };

    let flow_table = crate::core::flow::FlowTable::new(
        loaded.max_flows,
        std::time::Duration::from_secs(loaded.flow_idle_seconds as u64),
        loaded.max_packets_per_flow,
    );

    let stop_flag = stop_handler.flag();
    let mut engine = PassThroughEngine::new(
        capture,
        loaded.filter_engine,
        flow_table,
        strategy_impl,
        |counters| {
            eprintln!("[counters] processed={} reinserted={} modified={} errors={} dropped={}",
                counters.processed, counters.reinserted, counters.modified, counters.errors, counters.dropped);
        },
    );

    let result = engine.run(mode, stop_flag);
    let _ = stop_handler.close();

    match result {
        Ok(counters) => (0, format!(
            "Engine stopped normally.\nprocessed={} reinserted={} tcp={} udp={} ipv4={} ipv6={}\nmalformed={} unsupported={} errors={} dropped={}",
            counters.processed, counters.reinserted, counters.tcp, counters.udp,
            counters.ipv4, counters.ipv6, counters.malformed, counters.unsupported,
            counters.errors, counters.dropped,
        )),
        Err(e) => (1, format!("Engine error: {e:?}")),
    }
}
