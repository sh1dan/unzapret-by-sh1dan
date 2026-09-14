//! Runtime loader for config/default.toml and associated TXT lists.
//! Strict schema: unknown keys, disabled strategies, payload_logging=true,
//! wildcard IPs and zero/excessive limits all cause load failure.

use std::io::Read;
use std::path::Path;
use crate::capture::{CaptureError, ErrorKind};
use crate::filtering::list::{DomainEntry, IpEntry, ListError};
use crate::filtering::engine::{FilterEngine, TargetPreset};
use windivert_adapter::validated_file;

/// Maximum size of the main config file.
const MAX_CONFIG_BYTES: u64 = 16_384;
/// Maximum size of any TXT list file.
const MAX_LIST_BYTES: u64 = 65_536;
/// Maximum entries in any single TXT list.
const MAX_LIST_ENTRIES: usize = 4096;

fn cfg_err() -> CaptureError { CaptureError::new(ErrorKind::InvalidConfiguration, None) }

fn from_list(e: ListError) -> CaptureError {
    eprintln!("config list error: {e}");
    cfg_err()
}

/// Fully loaded and validated runtime configuration.
pub struct LoadedConfig {
    pub dry_run:            bool,
    pub max_flows:          usize,
    pub flow_idle_seconds:  u32,
    pub max_initial_bytes:  usize,
    pub max_packets_per_flow: u8,
    pub strategy:           String,
    pub filter_engine:      FilterEngine,
}

pub fn load_config(config_root: &Path) -> Result<LoadedConfig, CaptureError> {
    // ── Read and parse TOML ──────────────────────────────────────────────────
    let config_path = validated_file(config_root, "config/default.toml", ErrorKind::InvalidConfiguration)?;
    let text = read_bounded(&config_path, MAX_CONFIG_BYTES, ErrorKind::InvalidConfiguration)?;
    let value: toml::Value = text.parse().map_err(|_| cfg_err())?;
    let root = value.as_table().ok_or_else(cfg_err)?;

    // Validate no unexpected top-level keys.
    let known_top = ["schema_version", "engine", "targets", "filters", "strategy", "strategies", "logging"];
    for key in root.keys() {
        if !known_top.contains(&key.as_str()) {
            eprintln!("config: unknown key '{key}'");
            return Err(cfg_err());
        }
    }

    let schema = root.get("schema_version").and_then(|v| v.as_integer()).ok_or_else(cfg_err)?;
    if schema != 1 { return Err(cfg_err()); }

    // ── [engine] ─────────────────────────────────────────────────────────────
    let engine = root.get("engine").and_then(|v| v.as_table()).ok_or_else(cfg_err)?;
    let known_engine = ["dry_run", "max_flows", "flow_idle_seconds", "max_initial_bytes", "max_packets_per_flow"];
    for k in engine.keys() {
        if !known_engine.contains(&k.as_str()) { return Err(cfg_err()); }
    }
    let dry_run = engine.get("dry_run").and_then(|v| v.as_bool()).ok_or_else(cfg_err)?;
    let max_flows = engine.get("max_flows").and_then(|v| v.as_integer()).ok_or_else(cfg_err)?;
    let flow_idle_seconds = engine.get("flow_idle_seconds").and_then(|v| v.as_integer()).ok_or_else(cfg_err)?;
    let max_initial_bytes = engine.get("max_initial_bytes").and_then(|v| v.as_integer()).ok_or_else(cfg_err)?;
    let max_packets_per_flow = engine.get("max_packets_per_flow").and_then(|v| v.as_integer()).ok_or_else(cfg_err)?;

    if max_flows <= 0 || max_flows > 65536 { return Err(cfg_err()); }
    if flow_idle_seconds <= 0 || flow_idle_seconds > 3600 { return Err(cfg_err()); }
    if max_initial_bytes <= 0 || max_initial_bytes > 65536 { return Err(cfg_err()); }
    if max_packets_per_flow <= 0 || max_packets_per_flow > 32 { return Err(cfg_err()); }

    // ── [strategy] ───────────────────────────────────────────────────────────
    let strategy_table = root.get("strategy").and_then(|v| v.as_table()).ok_or_else(cfg_err)?;
    let strategy_name = strategy_table.get("name").and_then(|v| v.as_str()).ok_or_else(cfg_err)?;
    // Supported strategies: pass-through, split-tcp, auto
    let known_strategies = ["pass-through", "split-tcp", "auto"];
    if !known_strategies.contains(&strategy_name) {
        eprintln!("config: unknown/unimplemented strategy '{strategy_name}'");
        return Err(cfg_err());
    }

    // ── [logging] — validate but do not act on ────────────────────────────────
    if let Some(logging) = root.get("logging").and_then(|v| v.as_table()) {
        if logging.get("packet_payload_logging").and_then(|v| v.as_bool()) == Some(true) {
            eprintln!("config: packet_payload_logging=true is not permitted");
            return Err(cfg_err());
        }
    }

    // ── [filters] ────────────────────────────────────────────────────────────
    let filters = root.get("filters").and_then(|v| v.as_table()).ok_or_else(cfg_err)?;
    let known_filters = ["exclude_domains_file", "exclude_ips_file", "unknown_action"];
    for k in filters.keys() {
        if !known_filters.contains(&k.as_str()) { return Err(cfg_err()); }
    }

    let exclude_domains = load_domain_list(config_root, filters, "exclude_domains_file")?;
    let exclude_ips = load_ip_list(config_root, filters, "exclude_ips_file")?;

    // ── [targets.*] ──────────────────────────────────────────────────────────
    let targets_table = root.get("targets").and_then(|v| v.as_table()).ok_or_else(cfg_err)?;
    let known_targets = ["youtube", "discord", "twitch", "telegram", "discord_voice", "custom"];
    for k in targets_table.keys() {
        if !known_targets.contains(&k.as_str()) {
            eprintln!("config: unknown target '{k}'");
            return Err(cfg_err());
        }
    }

    let mut presets = Vec::new();
    for name in known_targets {
        if let Some(target) = targets_table.get(name).and_then(|v| v.as_table()) {
            let enabled = target.get("enabled").and_then(|v| v.as_bool()).ok_or_else(cfg_err)?;
            if !enabled { continue; }

            let allow_domains = load_domain_list(config_root, target, "domains_file")?;
            let allow_ips = load_ip_list(config_root, target, "ips_file")?;
            let tcp_ports = load_ports(target, "tcp_ports")?;
            let udp_ports = load_ports(target, "udp_ports")?;

            presets.push(TargetPreset { allow_domains, allow_ips, tcp_ports, udp_ports });
        }
    }

    Ok(LoadedConfig {
        dry_run,
        max_flows: max_flows as usize,
        flow_idle_seconds: flow_idle_seconds as u32,
        max_initial_bytes: max_initial_bytes as usize,
        max_packets_per_flow: max_packets_per_flow as u8,
        strategy: strategy_name.to_owned(),
        filter_engine: FilterEngine::new(exclude_ips, exclude_domains, presets),
    })
}

fn read_bounded(path: &Path, limit: u64, kind: ErrorKind) -> Result<String, CaptureError> {
    let file = std::fs::File::open(path).map_err(|e| CaptureError::from_io(kind, &e))?;
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)
        .map_err(|e| CaptureError::from_io(kind, &e))?;
    if text.len() as u64 > limit { return Err(CaptureError::new(kind, None)); }
    Ok(text)
}

fn load_domain_list(
    config_root: &Path,
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Vec<DomainEntry>, CaptureError> {
    let rel = match table.get(key).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(vec![]),
    };
    let path = validated_file(config_root, &format!("config/{rel}"), ErrorKind::InvalidConfiguration)?;
    let text = read_bounded(&path, MAX_LIST_BYTES, ErrorKind::InvalidConfiguration)?;
    let entries = crate::filtering::list::parse_domains(&text).map_err(from_list)?;
    if entries.len() > MAX_LIST_ENTRIES { return Err(cfg_err()); }
    Ok(entries)
}

fn load_ip_list(
    config_root: &Path,
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Vec<IpEntry>, CaptureError> {
    let rel = match table.get(key).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(vec![]),
    };
    let path = validated_file(config_root, &format!("config/{rel}"), ErrorKind::InvalidConfiguration)?;
    let text = read_bounded(&path, MAX_LIST_BYTES, ErrorKind::InvalidConfiguration)?;
    let entries = crate::filtering::list::parse_ips(&text).map_err(from_list)?;
    if entries.len() > MAX_LIST_ENTRIES { return Err(cfg_err()); }
    Ok(entries)
}

fn load_ports(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Vec<u16>, CaptureError> {
    let arr = table.get(key).and_then(|v| v.as_array()).ok_or_else(cfg_err)?;
    arr.iter().map(|v| {
        let n = v.as_integer().ok_or_else(cfg_err)?;
        u16::try_from(n).ok().filter(|&p| p != 0).ok_or_else(cfg_err)
    }).collect()
}
