//! Windows Service Control Manager (SCM) integration for Local DPI Bypass.
//! Enforces:
//! - Quoted ImagePath (CWE-428 mitigation)
//! - Admin privilege verification
//! - Service states and error mappings
//! - Graceful start/stop via SCM control dispatcher

use std::sync::atomic::AtomicBool;

pub const SERVICE_NAME: &str = "LocalDpiBypass";
pub const DISPLAY_NAME: &str = "Local DPI Bypass";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    MarkedForDelete,
    Unknown,
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceState::NotInstalled => write!(f, "Not Installed"),
            ServiceState::Stopped => write!(f, "Stopped"),
            ServiceState::StartPending => write!(f, "Start Pending"),
            ServiceState::StopPending => write!(f, "Stop Pending"),
            ServiceState::Running => write!(f, "Running"),
            ServiceState::ContinuePending => write!(f, "Continue Pending"),
            ServiceState::PausePending => write!(f, "Pause Pending"),
            ServiceState::Paused => write!(f, "Paused"),
            ServiceState::MarkedForDelete => write!(f, "Marked for Deletion"),
            ServiceState::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<windivert_adapter::ScmState> for ServiceState {
    fn from(s: windivert_adapter::ScmState) -> Self {
        match s {
            windivert_adapter::ScmState::NotInstalled => ServiceState::NotInstalled,
            windivert_adapter::ScmState::Stopped => ServiceState::Stopped,
            windivert_adapter::ScmState::StartPending => ServiceState::StartPending,
            windivert_adapter::ScmState::StopPending => ServiceState::StopPending,
            windivert_adapter::ScmState::Running => ServiceState::Running,
            windivert_adapter::ScmState::ContinuePending => ServiceState::ContinuePending,
            windivert_adapter::ScmState::PausePending => ServiceState::PausePending,
            windivert_adapter::ScmState::Paused => ServiceState::Paused,
            windivert_adapter::ScmState::MarkedForDelete => ServiceState::MarkedForDelete,
            windivert_adapter::ScmState::Unknown => ServiceState::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    NotImplemented,
    AccessDenied,
    ServiceNotFound,
    ServiceAlreadyExists,
    ServiceAlreadyRunning,
    ServiceNotActive,
    ServiceMarkedForDelete,
    OperatingSystem(u32),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::NotImplemented => write!(f, "Operation is not supported on this platform"),
            ServiceError::AccessDenied => write!(f, "Administrator privileges are required (Access Denied)"),
            ServiceError::ServiceNotFound => write!(f, "Service is not installed"),
            ServiceError::ServiceAlreadyExists => write!(f, "Service is already installed"),
            ServiceError::ServiceAlreadyRunning => write!(f, "Service is already running"),
            ServiceError::ServiceNotActive => write!(f, "Service is not currently running"),
            ServiceError::ServiceMarkedForDelete => write!(f, "Service is marked for deletion"),
            ServiceError::OperatingSystem(code) => write!(f, "Windows OS error code {code}"),
        }
    }
}

impl From<windivert_adapter::ScmError> for ServiceError {
    fn from(e: windivert_adapter::ScmError) -> Self {
        match e {
            windivert_adapter::ScmError::AccessDenied => ServiceError::AccessDenied,
            windivert_adapter::ScmError::ServiceNotFound => ServiceError::ServiceNotFound,
            windivert_adapter::ScmError::ServiceAlreadyExists => ServiceError::ServiceAlreadyExists,
            windivert_adapter::ScmError::ServiceAlreadyRunning => ServiceError::ServiceAlreadyRunning,
            windivert_adapter::ScmError::ServiceNotActive => ServiceError::ServiceNotActive,
            windivert_adapter::ScmError::ServiceMarkedForDelete => ServiceError::ServiceMarkedForDelete,
            windivert_adapter::ScmError::OperatingSystem(c) => ServiceError::OperatingSystem(c),
            windivert_adapter::ScmError::UnsupportedPlatform
            | windivert_adapter::ScmError::InvalidParameter => ServiceError::NotImplemented,
        }
    }
}

pub trait ServiceManager {
    fn status(&self) -> Result<ServiceState, ServiceError>;
    fn install(&self) -> Result<(), ServiceError>;
    fn remove(&self) -> Result<(), ServiceError>;
    fn start(&self) -> Result<(), ServiceError>;
    fn stop(&self) -> Result<(), ServiceError>;
    fn restart(&self) -> Result<(), ServiceError>;
}

/// Explicitly unavailable service manager used for platform-independent contract testing.
pub struct UnavailableService;

impl ServiceManager for UnavailableService {
    fn status(&self) -> Result<ServiceState, ServiceError> { Err(ServiceError::NotImplemented) }
    fn install(&self) -> Result<(), ServiceError> { Err(ServiceError::NotImplemented) }
    fn remove(&self) -> Result<(), ServiceError> { Err(ServiceError::NotImplemented) }
    fn start(&self) -> Result<(), ServiceError> { Err(ServiceError::NotImplemented) }
    fn stop(&self) -> Result<(), ServiceError> { Err(ServiceError::NotImplemented) }
    fn restart(&self) -> Result<(), ServiceError> { Err(ServiceError::NotImplemented) }
}

/// Windows Service Control Manager client.
pub struct WindowsService {
    pub service_name: &'static str,
    pub display_name: &'static str,
}

impl Default for WindowsService {
    fn default() -> Self {
        Self {
            service_name: SERVICE_NAME,
            display_name: DISPLAY_NAME,
        }
    }
}

impl ServiceManager for WindowsService {
    fn status(&self) -> Result<ServiceState, ServiceError> {
        let state = windivert_adapter::scm_query_status(self.service_name)?;
        Ok(state.into())
    }

    fn install(&self) -> Result<(), ServiceError> {
        let exe = std::env::current_exe().map_err(|_| ServiceError::NotImplemented)?;
        let quoted_cmd = windivert_adapter::build_quoted_service_command(&exe, "service run");
        windivert_adapter::scm_install_service(self.service_name, self.display_name, &quoted_cmd)?;
        Ok(())
    }

    fn remove(&self) -> Result<(), ServiceError> {
        windivert_adapter::scm_remove_service(self.service_name)?;
        Ok(())
    }

    fn start(&self) -> Result<(), ServiceError> {
        windivert_adapter::scm_start_service(self.service_name)?;
        Ok(())
    }

    fn stop(&self) -> Result<(), ServiceError> {
        windivert_adapter::scm_stop_service(self.service_name)?;
        Ok(())
    }

    fn restart(&self) -> Result<(), ServiceError> {
        windivert_adapter::scm_restart_service(self.service_name)?;
        Ok(())
    }
}

/// Dispatches CLI service commands.
pub fn dispatch_service_command(action: &str) -> (u8, String) {
    let service = WindowsService::default();
    match action {
        "status" => match service.status() {
            Ok(state) => (0, format!("Service: {} ({})\nStatus:  {state}", service.service_name, service.display_name)),
            Err(e) => (1, format!("Failed to query service status: {e}")),
        },
        "install" => match service.install() {
            Ok(()) => (0, format!("Service '{}' successfully installed (Auto-Start, quoted ImagePath).", service.service_name)),
            Err(e) => (1, format!("Service installation failed: {e}")),
        },
        "remove" => match service.remove() {
            Ok(()) => (0, format!("Service '{}' successfully stopped and removed.", service.service_name)),
            Err(e) => (1, format!("Service removal failed: {e}")),
        },
        "start" => match service.start() {
            Ok(()) => (0, format!("Service '{}' started successfully.", service.service_name)),
            Err(e) => (1, format!("Service start failed: {e}")),
        },
        "stop" => match service.stop() {
            Ok(()) => (0, format!("Service '{}' stopped successfully.", service.service_name)),
            Err(e) => (1, format!("Service stop failed: {e}")),
        },
        "restart" => match service.restart() {
            Ok(()) => (0, format!("Service '{}' restarted successfully.", service.service_name)),
            Err(e) => (1, format!("Service restart failed: {e}")),
        },
        "run" => run_service(),
        _ => (2, format!("Unknown service command '{action}'. Available: install | remove | status | start | stop | restart")),
    }
}

/// SCM Service runner entry point.
pub fn run_service() -> (u8, String) {
    let res = windivert_adapter::run_service_dispatcher(SERVICE_NAME, |stop_flag| {
        run_engine_as_service(stop_flag)
    });
    match res {
        Ok(()) => (0, "Service stopped normally.".into()),
        Err(e) => (1, format!("Service runner error: {e}")),
    }
}

fn run_engine_as_service(stop_flag: &AtomicBool) -> Result<(), String> {
    use crate::core::{RunMode, PacketEngine as _, pipeline::PassThroughEngine};
    use crate::core::phase2_config::Phase2Config;
    use crate::core::config_loader::load_config;
    use crate::capture::windivert::WinDivertCapture;

    let app_dir = windivert_adapter::application_dir()
        .map_err(|e| format!("Cannot determine application directory: {e}"))?;

    let loaded = load_config(&app_dir)
        .map_err(|e| format!("Configuration error: {e}"))?;

    let mode = if loaded.dry_run { RunMode::DryRun } else { RunMode::Active };

    let p2_config = Phase2Config::load().map(|(c, _)| c).ok();

    let dynamic_filter = loaded.filter_engine.build_windivert_filter();
    let capture = match WinDivertCapture::open_filter(&dynamic_filter, mode) {
        Ok(c) => c,
        Err(_) => {
            if let Some(ref p2) = p2_config {
                WinDivertCapture::open(p2, mode)
                    .map_err(|e| format!("Capture open failed: {e}"))?
            } else {
                return Err("Capture open failed: unable to initialize WinDivert driver".into());
            }
        }
    };

    let strategy_impl: Box<dyn crate::strategies::Strategy> = match loaded.strategy.as_str() {
        "split-tcp" => Box::new(crate::strategies::SplitTcp::default()),
        _ => Box::new(crate::strategies::PassThrough),
    };

    let flow_table = crate::core::flow::FlowTable::new(
        loaded.max_flows,
        std::time::Duration::from_secs(loaded.flow_idle_seconds as u64),
        loaded.max_packets_per_flow,
    );

    let mut engine = PassThroughEngine::new(
        capture,
        loaded.filter_engine,
        flow_table,
        strategy_impl,
        |_counters| {},
    );

    engine.run(mode, stop_flag).map_err(|e| format!("Engine execution error: {e:?}"))?;
    Ok(())
}
