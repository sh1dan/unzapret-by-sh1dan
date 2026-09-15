/// Compile-time schema only. TOML loading/validation arrives with filtering.
pub const EXAMPLE_TOML: &str = include_str!("../../config/default.toml");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Targets {
    pub youtube: bool,
    pub discord: bool,
    pub discord_voice: bool,
    pub custom: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_flows: usize,
    pub flow_idle_seconds: u32,
    pub max_initial_bytes: usize,
    pub max_packets_per_flow: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub schema_version: u32,
    pub targets: Targets,
    pub strategy: String,
    pub dry_run: bool,
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            targets: Targets {
                youtube: true,
                discord: true,
                discord_voice: false,
                custom: false,
            },
            strategy: "pass-through".into(),
            dry_run: true,
            limits: Limits {
                max_flows: 4096,
                flow_idle_seconds: 30,
                max_initial_bytes: 16384,
                max_packets_per_flow: 4,
            },
        }
    }
}
