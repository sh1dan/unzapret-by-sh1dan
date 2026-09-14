//! Windows Service Control Manager (SCM) FFI and safe wrappers.
//! Conforms to Windows Win32 Service architecture.
//! Only ffi/unsafe blocks are used here; the main crate maintains #![forbid(unsafe_code)].

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScmState {
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

impl std::fmt::Display for ScmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScmState::NotInstalled => write!(f, "Not Installed"),
            ScmState::Stopped => write!(f, "Stopped"),
            ScmState::StartPending => write!(f, "Start Pending"),
            ScmState::StopPending => write!(f, "Stop Pending"),
            ScmState::Running => write!(f, "Running"),
            ScmState::ContinuePending => write!(f, "Continue Pending"),
            ScmState::PausePending => write!(f, "Pause Pending"),
            ScmState::Paused => write!(f, "Paused"),
            ScmState::MarkedForDelete => write!(f, "Marked for Deletion"),
            ScmState::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScmError {
    AccessDenied,
    ServiceNotFound,
    ServiceAlreadyExists,
    ServiceAlreadyRunning,
    ServiceNotActive,
    ServiceMarkedForDelete,
    InvalidParameter,
    OperatingSystem(u32),
    UnsupportedPlatform,
}

impl std::fmt::Display for ScmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScmError::AccessDenied => write!(f, "Administrator privileges required (Access Denied)"),
            ScmError::ServiceNotFound => write!(f, "Service is not installed"),
            ScmError::ServiceAlreadyExists => write!(f, "Service is already installed"),
            ScmError::ServiceAlreadyRunning => write!(f, "Service is already running"),
            ScmError::ServiceNotActive => write!(f, "Service is not currently active"),
            ScmError::ServiceMarkedForDelete => write!(f, "Service is marked for deletion and pending cleanup"),
            ScmError::InvalidParameter => write!(f, "Invalid parameter passed to SCM"),
            ScmError::OperatingSystem(code) => write!(f, "Windows OS error {code}"),
            ScmError::UnsupportedPlatform => write!(f, "SCM is only supported on Windows"),
        }
    }
}

impl std::error::Error for ScmError {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceStatus {
    pub service_type: u32,
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub check_point: u32,
    pub wait_hint: u32,
}

const SC_MANAGER_CONNECT: u32 = 0x0001;
const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;

const SERVICE_QUERY_STATUS: u32 = 0x0004;
const SERVICE_START: u32 = 0x0010;
const SERVICE_STOP: u32 = 0x0020;
const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
const DELETE: u32 = 0x00010000;

const SERVICE_WIN32_OWN_PROCESS: u32 = 0x00000010;
const SERVICE_AUTO_START: u32 = 0x00000002;
const SERVICE_ERROR_NORMAL: u32 = 0x00000001;

const SERVICE_CONTROL_STOP: u32 = 0x00000001;
const SERVICE_CONTROL_SHUTDOWN: u32 = 0x00000005;

pub const SERVICE_ACCEPT_STOP: u32 = 0x00000001;
pub const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x00000004;

pub const SERVICE_STOPPED: u32 = 1;
pub const SERVICE_START_PENDING: u32 = 2;
pub const SERVICE_STOP_PENDING: u32 = 3;
pub const SERVICE_RUNNING: u32 = 4;
pub const SERVICE_CONTINUE_PENDING: u32 = 5;
pub const SERVICE_PAUSE_PENDING: u32 = 6;
pub const SERVICE_PAUSED: u32 = 7;

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
const ERROR_SERVICE_MARKED_FOR_DELETE: u32 = 1072;
const ERROR_SERVICE_EXISTS: u32 = 1073;

#[link(name = "advapi32")]
extern "system" {
    fn OpenSCManagerW(
        lpMachineName: *const u16,
        lpDatabaseName: *const u16,
        dwDesiredAccess: u32,
    ) -> *mut c_void;

    fn CreateServiceW(
        hSCManager: *mut c_void,
        lpServiceName: *const u16,
        lpDisplayName: *const u16,
        dwDesiredAccess: u32,
        dwServiceType: u32,
        dwStartType: u32,
        dwErrorControl: u32,
        lpBinaryPathName: *const u16,
        lpLoadOrderGroup: *const u16,
        lpdwTagId: *mut u32,
        lpDependencies: *const u16,
        lpServiceStartName: *const u16,
        lpPassword: *const u16,
    ) -> *mut c_void;

    fn OpenServiceW(
        hSCManager: *mut c_void,
        lpServiceName: *const u16,
        dwDesiredAccess: u32,
    ) -> *mut c_void;

    fn QueryServiceStatus(
        hService: *mut c_void,
        lpServiceStatus: *mut ServiceStatus,
    ) -> i32;

    fn StartServiceW(
        hService: *mut c_void,
        dwNumServiceArgs: u32,
        lpServiceArgVectors: *const *const u16,
    ) -> i32;

    fn ControlService(
        hService: *mut c_void,
        dwControl: u32,
        lpServiceStatus: *mut ServiceStatus,
    ) -> i32;

    fn DeleteService(hService: *mut c_void) -> i32;

    fn CloseServiceHandle(hSCObject: *mut c_void) -> i32;

    fn StartServiceCtrlDispatcherW(lpServiceTable: *const ServiceTableEntryW) -> i32;

    fn RegisterServiceCtrlHandlerExW(
        lpServiceName: *const u16,
        lpHandlerProc: Option<HandlerExFn>,
        lpContext: *mut c_void,
    ) -> *mut c_void;

    fn SetServiceStatus(
        hServiceStatus: *mut c_void,
        lpServiceStatus: *const ServiceStatus,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
    fn Sleep(dwMilliseconds: u32);
}

type HandlerExFn = unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32;

#[repr(C)]
pub struct ServiceTableEntryW {
    pub service_name: *const u16,
    pub service_proc: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn map_last_error() -> ScmError {
    let code = unsafe { GetLastError() };
    match code {
        ERROR_ACCESS_DENIED => ScmError::AccessDenied,
        ERROR_SERVICE_DOES_NOT_EXIST => ScmError::ServiceNotFound,
        ERROR_SERVICE_ALREADY_RUNNING => ScmError::ServiceAlreadyRunning,
        ERROR_SERVICE_NOT_ACTIVE => ScmError::ServiceNotActive,
        ERROR_SERVICE_MARKED_FOR_DELETE => ScmError::ServiceMarkedForDelete,
        ERROR_SERVICE_EXISTS => ScmError::ServiceAlreadyExists,
        _ => ScmError::OperatingSystem(code),
    }
}

/// Builds a strictly quoted binary command string for ImagePath to prevent CWE-428 vulnerabilities.
pub fn build_quoted_service_command(exe_path: &Path, subcommand: &str) -> String {
    format!("\"{}\" {}", exe_path.display(), subcommand)
}

struct ScHandle(*mut c_void);
impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

/// Queries the current status of a Windows service by name.
pub fn scm_query_status(name: &str) -> Result<ScmState, ScmError> {
    let scm = ScHandle(unsafe {
        OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT)
    });
    if scm.0.is_null() {
        return Err(map_last_error());
    }

    let wide_name = to_wide(name);
    let service = ScHandle(unsafe {
        OpenServiceW(scm.0, wide_name.as_ptr(), SERVICE_QUERY_STATUS)
    });
    if service.0.is_null() {
        let err = map_last_error();
        if err == ScmError::ServiceNotFound {
            return Ok(ScmState::NotInstalled);
        }
        return Err(err);
    }

    let mut status = ServiceStatus::default();
    let res = unsafe { QueryServiceStatus(service.0, &mut status) };
    if res == 0 {
        return Err(map_last_error());
    }

    let state = match status.current_state {
        SERVICE_STOPPED => ScmState::Stopped,
        SERVICE_START_PENDING => ScmState::StartPending,
        SERVICE_STOP_PENDING => ScmState::StopPending,
        SERVICE_RUNNING => ScmState::Running,
        SERVICE_CONTINUE_PENDING => ScmState::ContinuePending,
        SERVICE_PAUSE_PENDING => ScmState::PausePending,
        SERVICE_PAUSED => ScmState::Paused,
        _ => ScmState::Unknown,
    };
    Ok(state)
}

/// Installs an auto-start Windows service with quoted binary path.
pub fn scm_install_service(
    name: &str,
    display_name: &str,
    quoted_binary_path: &str,
) -> Result<(), ScmError> {
    let scm = ScHandle(unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    });
    if scm.0.is_null() {
        return Err(map_last_error());
    }

    let wide_name = to_wide(name);
    let wide_display = to_wide(display_name);
    let wide_bin = to_wide(quoted_binary_path);

    let service = ScHandle(unsafe {
        CreateServiceW(
            scm.0,
            wide_name.as_ptr(),
            wide_display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            wide_bin.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    });

    if service.0.is_null() {
        return Err(map_last_error());
    }

    Ok(())
}

/// Stops the service if running and removes it from the Windows Service Control Manager.
pub fn scm_remove_service(name: &str) -> Result<(), ScmError> {
    let scm = ScHandle(unsafe {
        OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS)
    });
    if scm.0.is_null() {
        return Err(map_last_error());
    }

    let wide_name = to_wide(name);
    let service = ScHandle(unsafe {
        OpenServiceW(
            scm.0,
            wide_name.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
        )
    });
    if service.0.is_null() {
        return Err(map_last_error());
    }

    // Attempt to stop before deleting
    let mut status = ServiceStatus::default();
    unsafe {
        ControlService(service.0, SERVICE_CONTROL_STOP, &mut status);
    }

    let del = unsafe { DeleteService(service.0) };
    if del == 0 {
        return Err(map_last_error());
    }

    Ok(())
}

/// Starts an installed Windows service.
pub fn scm_start_service(name: &str) -> Result<(), ScmError> {
    let scm = ScHandle(unsafe {
        OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT)
    });
    if scm.0.is_null() {
        return Err(map_last_error());
    }

    let wide_name = to_wide(name);
    let service = ScHandle(unsafe {
        OpenServiceW(scm.0, wide_name.as_ptr(), SERVICE_START | SERVICE_QUERY_STATUS)
    });
    if service.0.is_null() {
        return Err(map_last_error());
    }

    let res = unsafe { StartServiceW(service.0, 0, std::ptr::null()) };
    if res == 0 {
        return Err(map_last_error());
    }

    Ok(())
}

/// Stops a running Windows service and waits for stopped state.
pub fn scm_stop_service(name: &str) -> Result<(), ScmError> {
    let scm = ScHandle(unsafe {
        OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT)
    });
    if scm.0.is_null() {
        return Err(map_last_error());
    }

    let wide_name = to_wide(name);
    let service = ScHandle(unsafe {
        OpenServiceW(scm.0, wide_name.as_ptr(), SERVICE_STOP | SERVICE_QUERY_STATUS)
    });
    if service.0.is_null() {
        return Err(map_last_error());
    }

    let mut status = ServiceStatus::default();
    let res = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
    if res == 0 {
        return Err(map_last_error());
    }

    // Wait up to 5 seconds for service to reach stopped state
    for _ in 0..50 {
        let q = unsafe { QueryServiceStatus(service.0, &mut status) };
        if q != 0 && status.current_state == SERVICE_STOPPED {
            return Ok(());
        }
        unsafe { Sleep(100) };
    }

    Ok(())
}

/// Restarts a Windows service (stop, wait, start).
pub fn scm_restart_service(name: &str) -> Result<(), ScmError> {
    let _ = scm_stop_service(name);
    scm_start_service(name)
}

/// Windows Service Dispatcher entry point.
/// Must be invoked when the binary is run with `service run`.
pub fn run_service_dispatcher<F>(service_name: &str, runner: F) -> Result<(), ScmError>
where
    F: FnMut(&std::sync::atomic::AtomicBool) -> Result<(), String> + Send + 'static,
{
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    static STOP_FLAG: AtomicBool = AtomicBool::new(false);
    static STATUS_HANDLE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn control_handler(
        control: u32,
        _: u32,
        _: *mut c_void,
        _: *mut c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                STOP_FLAG.store(true, Ordering::SeqCst);
                let val = STATUS_HANDLE.load(Ordering::SeqCst);
                if val != 0 {
                    let h = val as *mut c_void;
                    let status = ServiceStatus {
                        service_type: SERVICE_WIN32_OWN_PROCESS,
                        current_state: SERVICE_STOP_PENDING,
                        controls_accepted: 0,
                        win32_exit_code: 0,
                        service_specific_exit_code: 0,
                        check_point: 1,
                        wait_hint: 5000,
                    };
                    SetServiceStatus(h, &status);
                }
                0 // NO_ERROR
            }
            _ => 120, // ERROR_CALL_NOT_IMPLEMENTED
        }
    }

    // Note: StartServiceCtrlDispatcherW connects the calling thread to SCM.
    // In our implementation, we create the table entry and invoke dispatcher.
    let wide_name = to_wide(service_name);
    let table = [
        ServiceTableEntryW {
            service_name: wide_name.as_ptr(),
            service_proc: Some(service_main),
        },
        ServiceTableEntryW {
            service_name: std::ptr::null(),
            service_proc: None,
        },
    ];

    // Wrap the user runner closure in a boxed thread-safe cell
    static RUNNER: Mutex<Option<Box<dyn FnMut(&AtomicBool) -> Result<(), String> + Send>>> =
        Mutex::new(None);

    unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
        let wide_name = to_wide("LocalDpiBypass");
        let handle = RegisterServiceCtrlHandlerExW(
            wide_name.as_ptr(),
            Some(control_handler),
            std::ptr::null_mut(),
        );
        if handle.is_null() {
            return;
        }

        STATUS_HANDLE.store(handle as usize, Ordering::SeqCst);

        let running_status = ServiceStatus {
            service_type: SERVICE_WIN32_OWN_PROCESS,
            current_state: SERVICE_RUNNING,
            controls_accepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            win32_exit_code: 0,
            service_specific_exit_code: 0,
            check_point: 0,
            wait_hint: 0,
        };
        SetServiceStatus(handle, &running_status);

        if let Ok(mut guard) = RUNNER.lock() {
            if let Some(ref mut run) = *guard {
                let _ = run(&STOP_FLAG);
            }
        }

        let stopped_status = ServiceStatus {
            service_type: SERVICE_WIN32_OWN_PROCESS,
            current_state: SERVICE_STOPPED,
            controls_accepted: 0,
            win32_exit_code: 0,
            service_specific_exit_code: 0,
            check_point: 0,
            wait_hint: 0,
        };
        SetServiceStatus(handle, &stopped_status);
    }

    if let Ok(mut guard) = RUNNER.lock() {
        *guard = Some(Box::new(runner));
    }

    let res = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if res == 0 {
        return Err(map_last_error());
    }

    Ok(())
}
