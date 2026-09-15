pub const HELP: &str = "Local DPI Bypass — TCP-only test candidate (voice/QUIC bypass unavailable)
Implemented: start [--dry-run] | status | strategies | config show | test [--mock]
             service install | remove | status | start | stop | restart
             diagnose | logs | help
Reserved (Phase 10): restart | use <strategy>
Reserved commands return exit code 2 without side effects.
Administrator privileges and WinDivert/WinDivert64.sys are required for start and service.";

pub struct Reply {
    pub code: u8,
    pub text: String,
}

/// Pure dispatch: no filesystem, network, registry or SCM access for read-only commands.
/// `start` is the one command that opens captures and requires administrator privileges.
pub fn dispatch(args: &[&str]) -> Reply {
    let (code, text) = match args {
        ["--version"] | ["version"] => (0, format!("Local DPI Bypass {} (TCP-only candidate)", env!("CARGO_PKG_VERSION"))),
        [] | ["help"] | ["--help"] | ["-h"] => (0, HELP.to_owned()),
        ["status"] => (0, format!("Version: {}\nEngine: TCP-only candidate\nService: not queried (use 'service status')\nStrategy: pass-through / split-tcp\nVoice/QUIC bypass: unavailable\nConfiguration: use 'config show'\nCounters: shown only by the running console", env!("CARGO_PKG_VERSION"))),
        ["strategies"] => (0, "pass-through: active — byte-exact reinject, no modification\nsplit-tcp: active — initial TCP payload segmentation\nauto / split-tls / reorder / decoy / quic / stun: unavailable in runtime".into()),
        ["config", "show"] => show_config(),
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

fn show_config() -> (u8, String) {
    use std::io::Read;
    let result = (|| -> Result<String, crate::capture::CaptureError> {
        let root = windivert_adapter::application_dir()?;
        crate::core::config_loader::load_config(&root)?;
        let path = windivert_adapter::validated_file(
            &root,
            "config/default.toml",
            crate::capture::ErrorKind::InvalidConfiguration,
        )?;
        let file = std::fs::File::open(path).map_err(|e| {
            crate::capture::CaptureError::from_io(
                crate::capture::ErrorKind::InvalidConfiguration,
                &e,
            )
        })?;
        let mut text = String::new();
        file.take(16384).read_to_string(&mut text).map_err(|e| {
            crate::capture::CaptureError::from_io(
                crate::capture::ErrorKind::InvalidConfiguration,
                &e,
            )
        })?;
        Ok(text)
    })();
    match result {
        Ok(text) => (0, text),
        Err(error) => (
            1,
            format!("Cannot load application config/default.toml: {error}"),
        ),
    }
}

fn run_engine(dry_run: bool) -> (u8, String) {
    use crate::capture::windivert::WinDivertCapture;
    use crate::core::config_loader::load_config;
    use crate::core::{pipeline::PassThroughEngine, PacketEngine as _, RunMode};

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
    let mode = if effective_dry_run {
        RunMode::DryRun
    } else {
        RunMode::Active
    };
    let mode_label = if effective_dry_run {
        "dry-run (sniff)"
    } else {
        "active (capture+reinject)"
    };

    // Open the requested filter; preserve the original OS failure on error.
    let dynamic_filter = loaded.filter_engine.build_windivert_filter();
    let capture = match WinDivertCapture::open_filter(&dynamic_filter, mode) {
        Ok(capture) => capture,
        Err(error) => return (1, format!("Capture open failed: {error}")),
    };

    let mut stop_handler = match windivert_adapter::ConsoleStop::install() {
        Ok(h) => h,
        Err(e) => return (1, format!("Ctrl+C handler install failed: {e}")),
    };

    eprintln!(
        "unzapret-by-sh1dan {} engine started.",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("  Mode:     {mode_label}");
    eprintln!("  Strategy: {}", loaded.strategy);
    eprintln!(
        "  Config:   {}",
        app_dir.join("config/default.toml").display()
    );
    eprintln!("  Presets:  {} enabled", loaded.filter_engine.presets.len());
    eprintln!("  Voice/QUIC bypass: unavailable; UDP is not modified by split-tcp.");
    eprintln!(
        "  Max flows: {}, idle {}s, initial pkts: {}",
        loaded.max_flows, loaded.flow_idle_seconds, loaded.max_packets_per_flow
    );
    eprintln!("Press Ctrl+C to stop.");

    let strategy_impl = match crate::strategies::create(&loaded.strategy) {
        Ok(strategy) => strategy,
        Err(error) => return (1, format!("Unsupported strategy: {error}")),
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
            eprintln!("[counters] {counters}");
        },
    );

    let result = engine.run(mode, stop_flag);
    eprintln!("[final counters] {}", engine.counters());
    if let Err(error) = stop_handler.close() {
        return (1, format!("Console handler cleanup failed: {error}"));
    }

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
