//! Small platform boundary. Only ffi.rs may contain unsafe code.
#![deny(unsafe_code)]

use std::{
    fmt,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    AlreadyRunning,
    DriverNotFound,
    DllLoadFailed,
    DriverOpenFailed,
    AccessDenied,
    InvalidFilter,
    Receive,
    Send,
    Shutdown,
    InvalidPacket,
    UnsupportedPlatform,
    InvalidConfiguration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureError {
    pub kind: ErrorKind,
    pub os_code: Option<u32>,
}

impl CaptureError {
    pub const fn new(kind: ErrorKind, os_code: Option<u32>) -> Self {
        Self { kind, os_code }
    }
    pub fn from_io(kind: ErrorKind, error: &std::io::Error) -> Self {
        Self::new(kind, error.raw_os_error().map(|n| n as u32))
    }
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            ErrorKind::AlreadyRunning => "Another Local DPI Bypass capture is running; stop its console/service before starting this one",
            ErrorKind::DriverNotFound => "Local WinDivert.dll/WinDivert64.sys files are missing",
            ErrorKind::DllLoadFailed => "Trusted WinDivert DLL loading failed; check path, bitness and exports",
            ErrorKind::DriverOpenFailed => "WinDivert driver could not open; check signature, version and driver conflicts",
            ErrorKind::AccessDenied => "Administrator privileges are required, or access was denied",
            ErrorKind::InvalidFilter => "WinDivert rejected the capture filter",
            ErrorKind::Receive => "Packet receive failed; capture is stopping",
            ErrorKind::Send => "Packet reinjection failed or timed out; packet will not be retried",
            ErrorKind::Shutdown => "Capture shutdown/cleanup failed or timed out",
            ErrorKind::InvalidPacket => "Driver returned an incomplete or oversized packet",
            ErrorKind::UnsupportedPlatform => "Capture requires Windows x86_64",
            ErrorKind::InvalidConfiguration => "Invalid configuration: check profile name, enabled flags, limits and allowlists",
        };
        write!(f, "{message}")?;
        if let Some(code) = self.os_code {
            write!(f, " (OS error {code})")?;
        }
        Ok(())
    }
}
impl std::error::Error for CaptureError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Active,
    Sniff,
}

/// Opaque WinDivert 2.2 address: 80 bytes, alignment 8, no packet-related Debug.
#[repr(C, align(8))]
#[derive(Clone, PartialEq, Eq)]
pub struct Address {
    bytes: [u8; 80],
}

impl Default for Address {
    fn default() -> Self {
        Self { bytes: [0; 80] }
    }
}

pub struct Packet {
    pub bytes: Vec<u8>,
    pub address: Address,
}
pub enum Poll {
    Packet(Packet),
    Idle,
    End,
}

pub fn application_dir() -> Result<PathBuf, CaptureError> {
    let executable = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| CaptureError::from_io(ErrorKind::DllLoadFailed, &e))?;
    executable
        .parent()
        .map(Path::to_path_buf)
        .ok_or(CaptureError::new(ErrorKind::DllLoadFailed, None))
}

/// Only fixed relative application paths are passed by the executable.
/// Reject links/reparse points rather than allowing a canonical-path escape.
pub fn validated_file(
    root: &Path,
    relative: &str,
    kind: ErrorKind,
) -> Result<PathBuf, CaptureError> {
    let invalid = || CaptureError::new(kind, None);
    if !root.is_absolute() {
        return Err(invalid());
    }
    let root = root
        .canonicalize()
        .map_err(|e| CaptureError::from_io(kind, &e))?;
    let relative = Path::new(relative);
    let mut path = root.clone();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(invalid());
        };
        path.push(name);
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|e| CaptureError::from_io(kind, &e))?;
        if metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid());
            }
        }
    }
    let canonical = path
        .canonicalize()
        .map_err(|e| CaptureError::from_io(kind, &e))?;
    if !canonical.starts_with(&root) || !canonical.is_file() {
        return Err(invalid());
    }
    Ok(canonical)
}

pub fn driver_files() -> Result<(PathBuf, PathBuf), CaptureError> {
    let root = application_dir()?;
    Ok((
        validated_file(&root, "WinDivert/WinDivert.dll", ErrorKind::DriverNotFound)?,
        validated_file(
            &root,
            "WinDivert/WinDivert64.sys",
            ErrorKind::DriverNotFound,
        )?,
    ))
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod ffi;
#[cfg(all(windows, target_arch = "x86_64"))]
pub use ffi::{require_administrator, Capture, ConsoleStop};

#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub mod scm;
#[cfg(all(windows, target_arch = "x86_64"))]
pub use scm::*;

#[cfg(not(all(windows, target_arch = "x86_64")))]
mod unsupported {
    use super::*;
    fn error() -> CaptureError {
        CaptureError::new(ErrorKind::UnsupportedPlatform, None)
    }
    pub struct Capture;
    impl Capture {
        pub fn open(_: &str, _: Mode) -> Result<Self, CaptureError> {
            Err(error())
        }
        pub fn receive(&mut self) -> Result<Poll, CaptureError> {
            Err(error())
        }
        pub fn send(&mut self, _: &[u8], _: &Address) -> Result<(), CaptureError> {
            Err(error())
        }
        pub fn shutdown_receive(&mut self) -> Result<(), CaptureError> {
            Err(error())
        }
        pub fn close(&mut self) -> Result<(), CaptureError> {
            Ok(())
        }
    }
    pub struct ConsoleStop;
    impl ConsoleStop {
        pub fn install() -> Result<Self, CaptureError> {
            Err(error())
        }
        pub fn flag(&self) -> &std::sync::atomic::AtomicBool {
            static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            &STOP
        }
        pub fn close(&mut self) -> Result<(), CaptureError> {
            Ok(())
        }
    }
    pub fn require_administrator() -> Result<(), CaptureError> {
        Err(error())
    }

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
            write!(f, "{:?}", self)
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
            write!(f, "SCM is not supported on this platform")
        }
    }
    impl std::error::Error for ScmError {}

    pub fn build_quoted_service_command(exe_path: &Path, subcommand: &str) -> String {
        format!("\"{}\" {}", exe_path.display(), subcommand)
    }

    pub fn scm_query_status(_: &str) -> Result<ScmState, ScmError> {
        Err(ScmError::UnsupportedPlatform)
    }
    pub fn scm_install_service(_: &str, _: &str, _: &str) -> Result<(), ScmError> {
        Err(ScmError::UnsupportedPlatform)
    }
    pub fn scm_remove_service(_: &str) -> Result<(), ScmError> {
        Err(ScmError::UnsupportedPlatform)
    }
    pub fn scm_start_service(_: &str) -> Result<(), ScmError> {
        Err(ScmError::UnsupportedPlatform)
    }
    pub fn scm_stop_service(_: &str) -> Result<(), ScmError> {
        Err(ScmError::UnsupportedPlatform)
    }
    pub fn scm_restart_service(_: &str) -> Result<(), ScmError> {
        Err(ScmError::UnsupportedPlatform)
    }
    pub fn run_service_dispatcher<F>(_: &str, _: F) -> Result<(), ScmError>
    where
        F: FnMut(&std::sync::atomic::AtomicBool) -> Result<(), String> + 'static,
    {
        Err(ScmError::UnsupportedPlatform)
    }
}
#[cfg(not(all(windows, target_arch = "x86_64")))]
pub use unsupported::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn address_abi() {
        assert_eq!(std::mem::size_of::<Address>(), 80);
        assert_eq!(std::mem::align_of::<Address>(), 8);
    }
    #[test]
    fn paths_reject_parent_and_absolute_input() {
        let root = application_dir().unwrap();
        assert!(validated_file(&root, "../escape.dll", ErrorKind::DllLoadFailed).is_err());
        assert!(validated_file(&root, "/escape.dll", ErrorKind::DllLoadFailed).is_err());
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    #[test]
    fn platform_error_is_explicit() {
        assert!(matches!(
            Capture::open("false", Mode::Active),
            Err(CaptureError {
                kind: ErrorKind::UnsupportedPlatform,
                ..
            })
        ));
    }
    #[test]
    fn quoted_service_command_protects_against_cwe_428() {
        let path = Path::new(r"C:\Program Files\Local DPI Bypass\dpi-bypass.exe");
        let cmd = build_quoted_service_command(path, "service run");
        assert_eq!(
            cmd,
            r#""C:\Program Files\Local DPI Bypass\dpi-bypass.exe" service run"#
        );
        assert!(cmd.starts_with('"'));
        assert!(cmd.contains(r#".exe" "#));
    }
}
