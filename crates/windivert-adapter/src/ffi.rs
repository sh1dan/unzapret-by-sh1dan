//! The only unsafe boundary: x86_64 Windows ABI, WinDivert 2.2 API.
use super::*;
use std::{ffi::{c_void, CString}, fs::{File, OpenOptions}, os::windows::{ffi::OsStrExt, fs::OpenOptionsExt}, ptr, rc::Rc, sync::atomic::{AtomicBool, Ordering}};

type Handle = *mut c_void;
const NO_DATA: u32 = 232;
const IO_PENDING: u32 = 997;
const IO_INCOMPLETE: u32 = 996;
const WAIT_TIMEOUT: u32 = 258;
const MAX_PACKET: usize = 65575;

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: Handle,
}

// WinDivert uses the C ABI, Windows APIs use system ABI. On supported x64
// their calling conventions coincide, but the declarations remain explicit.
type Open = unsafe extern "C" fn(*const i8, i32, i16, u64) -> Handle;
type RecvEx = unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, u64, *mut Address, *mut u32, *mut Overlapped) -> i32;
type SendEx = unsafe extern "C" fn(Handle, *const c_void, u32, *mut u32, u64, *const Address, u32, *mut Overlapped) -> i32;
type Shutdown = unsafe extern "C" fn(Handle, i32) -> i32;
type Close = unsafe extern "C" fn(Handle) -> i32;
type GetParam = unsafe extern "C" fn(Handle, i32, *mut u64) -> i32;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(path: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
    fn GetLastError() -> u32;
    fn CreateEventW(attributes: *const c_void, manual: i32, initial: i32, name: *const u16) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn GetOverlappedResult(handle: Handle, overlapped: *mut Overlapped, bytes: *mut u32, wait: i32) -> i32;
    fn CancelIoEx(handle: Handle, overlapped: *mut Overlapped) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
}
#[link(name = "advapi32")]
extern "system" {
    fn CreateWellKnownSid(kind: i32, domain: *const c_void, sid: *mut c_void, bytes: *mut u32) -> i32;
    fn CheckTokenMembership(token: Handle, sid: *const c_void, member: *mut i32) -> i32;
}

fn last() -> u32 {
    // SAFETY: thread-local numeric error, no pointers or borrowed storage.
    unsafe { GetLastError() }
}
fn error(kind: ErrorKind) -> CaptureError { CaptureError::new(kind, Some(last())) }

pub fn require_administrator() -> Result<(), CaptureError> {
    let mut sid = [0u32; 17];
    let mut size = 68u32;
    let mut member = 0;
    // SAFETY: 68-byte aligned owned SID buffer and live size/member outputs;
    // null token selects current effective token; no retained pointers.
    unsafe {
        if CreateWellKnownSid(26, ptr::null(), sid.as_mut_ptr().cast(), &mut size) == 0 {
            return Err(error(ErrorKind::AccessDenied));
        }
        if CheckTokenMembership(ptr::null_mut(), sid.as_ptr().cast(), &mut member) == 0 {
            return Err(error(ErrorKind::AccessDenied));
        }
    }
    if member == 0 { return Err(CaptureError::new(ErrorKind::AccessDenied, Some(5))); }
    Ok(())
}

struct Library(Handle);
impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: owned non-null module; all function users retain Rc<Api>.
        if unsafe { FreeLibrary(self.0) } == 0 {
            eprintln!("{}", error(ErrorKind::DllLoadFailed));
        }
    }
}

struct Api {
    _library: Library,
    // No FILE_SHARE_WRITE/DELETE: pins local files against replacement while loaded.
    _files: [File; 2],
    open: Open,
    recv: RecvEx,
    send: SendEx,
    shutdown: Shutdown,
    close: Close,
    get_param: GetParam,
}

impl Api {
    fn load() -> Result<Rc<Self>, CaptureError> {
        let (dll, sys) = driver_files()?;
        // Reject remote paths: no network DLL loading from a UNC application dir.
        if dll.to_string_lossy().starts_with(r"\\?\UNC\") {
            return Err(CaptureError::new(ErrorKind::DllLoadFailed, None));
        }
        let lock = |path: &Path| OpenOptions::new().read(true).share_mode(1).open(path)
            .map_err(|e| CaptureError::from_io(ErrorKind::DllLoadFailed, &e));
        let files = [lock(&dll)?, lock(&sys)?];
        // Revalidate after opening; only fixed application-relative paths are accepted.
        if driver_files()? != (dll.clone(), sys) {
            return Err(CaptureError::new(ErrorKind::DllLoadFailed, None));
        }
        let wide: Vec<u16> = dll.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: NUL-terminated absolute UTF-16 path lives through call; no file
        // handle supplied. DLL dependencies search SYSTEM32 only, never CWD/PATH.
        let module = unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), 0x800) };
        if module.is_null() { return Err(error(ErrorKind::DllLoadFailed)); }
        let library = Library(module);
        macro_rules! symbol {
            ($name:literal, $ty:ty) => {{
                // SAFETY: owned loaded module; literal is NUL-terminated. Function
                // signature below matches the official WinDivert 2.2 header.
                let raw = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
                if raw.is_null() { return Err(error(ErrorKind::DllLoadFailed)); }
                // SAFETY: non-null exported function, exact x64 ABI/signature;
                // module stays alive for the lifetime of Api and all pending I/O.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(raw) }
            }};
        }
        Ok(Rc::new(Self {
            open: symbol!("WinDivertOpen", Open), recv: symbol!("WinDivertRecvEx", RecvEx),
            send: symbol!("WinDivertSendEx", SendEx), shutdown: symbol!("WinDivertShutdown", Shutdown),
            close: symbol!("WinDivertClose", Close), get_param: symbol!("WinDivertGetParam", GetParam),
            _library: library, _files: files,
        }))
    }
}

/// Heap-pinned by Box ownership while I/O is pending. Fields never move then.
struct Io {
    data: Vec<u8>,
    address: Address,
    length: u32,
    address_length: u32,
    overlapped: Overlapped,
}
impl Io {
    fn new(data: Vec<u8>, address: Address) -> Result<Box<Self>, CaptureError> {
        // SAFETY: unnamed manual-reset event; no borrowed attributes/name.
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() { return Err(error(ErrorKind::Receive)); }
        Ok(Box::new(Self { data, address, length: 0, address_length: 80,
            overlapped: Overlapped { internal: 0, internal_high: 0, offset: 0, offset_high: 0, event } }))
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        // SAFETY: Io is dropped only after completion, never while kernel owns
        // its pointers. Uncompleted I/O is quarantined by close(), not dropped.
        if unsafe { CloseHandle(self.overlapped.event) } == 0 {
            eprintln!("{}", error(ErrorKind::Shutdown));
        }
    }
}

pub struct Capture {
    api: Rc<Api>,
    handle: Handle,
    mode: Mode,
    pending: Option<Box<Io>>,
    stopped: bool,
}

impl Capture {
    pub fn open(filter: &str, mode: Mode) -> Result<Self, CaptureError> {
        require_administrator()?;
        if filter.len() > 16384 { return Err(CaptureError::new(ErrorKind::InvalidFilter, None)); }
        let filter = CString::new(filter).map_err(|_| CaptureError::new(ErrorKind::InvalidFilter, None))?;
        let api = Api::load()?;
        let flags = if mode == Mode::Sniff { 0x1 | 0x4 } else { 0 };
        // SAFETY: filter is live NUL-terminated ASCII; NETWORK=0, priority=0,
        // supported flags; function pointer retained by owned api.
        let handle = unsafe { (api.open)(filter.as_ptr(), 0, 0, flags) };
        if handle as isize == -1 || handle.is_null() {
            let code = last();
            let kind = match code { 2 | 3 => ErrorKind::DriverNotFound, 5 => ErrorKind::AccessDenied,
                87 => ErrorKind::InvalidFilter, _ => ErrorKind::DriverOpenFailed };
            return Err(CaptureError::new(kind, Some(code)));
        }
        let mut capture = Self { api, handle, mode, pending: None, stopped: false };
        let mut major = 0;
        let mut minor = 0;
        // SAFETY: valid owned handle and live u64 output storage, no retention.
        let ok = unsafe { (capture.api.get_param)(handle, 3, &mut major) != 0
            && (capture.api.get_param)(handle, 4, &mut minor) != 0 };
        if !ok {
            let e = error(ErrorKind::DriverOpenFailed);
            let _ = capture.close();
            return Err(e);
        }
        if major != 2 || minor < 2 {
            let _ = capture.close();
            return Err(CaptureError::new(ErrorKind::DriverOpenFailed, None));
        }
        Ok(capture)
    }

    /// Waits without freeing/moving kernel-owned buffers on timeout.
    fn wait(&mut self, timeout: u32, kind: ErrorKind) -> Result<bool, CaptureError> {
        let io = self.pending.as_mut().ok_or(CaptureError::new(kind, None))?;
        // SAFETY: live event associated with the sole pending operation.
        let wait = unsafe { WaitForSingleObject(io.overlapped.event, timeout) };
        if wait == WAIT_TIMEOUT { return Ok(false); }
        if wait != 0 { return Err(error(kind)); }
        let mut transferred = 0;
        // SAFETY: matching handle/OVERLAPPED; Box and buffers have not moved;
        // nonblocking query after event signal. Output pointer lives through call.
        let ok = unsafe { GetOverlappedResult(self.handle, &mut io.overlapped, &mut transferred, 0) };
        if ok == 0 {
            let code = last();
            if code == IO_INCOMPLETE { return Ok(false); }
            // Event is signalled and I/O terminal, so buffers may now be released.
            self.pending.take();
            return Err(CaptureError::new(kind, Some(code)));
        }
        // In asynchronous/overlapped mode, GetOverlappedResult returns the actual
        // transferred byte count in transferred (WinDivert's synchronous pRecvLen
        // pointer is not written by WinDivert.dll on ERROR_IO_PENDING).
        if io.length == 0 {
            io.length = transferred;
        }
        Ok(true)
    }

    fn receive_failure(&self, error: CaptureError) -> Result<Poll, CaptureError> {
        if error.os_code == Some(NO_DATA) && self.stopped { return Ok(Poll::End); }
        if error.os_code == Some(122) {
            return Err(CaptureError::new(ErrorKind::InvalidPacket, error.os_code));
        }
        Err(error)
    }

    pub fn receive(&mut self) -> Result<Poll, CaptureError> {
        if self.handle.is_null() { return Err(CaptureError::new(ErrorKind::Receive, None)); }
        let mut synchronous = false;
        if self.pending.is_none() {
            let mut io = Io::new(vec![0; MAX_PACKET], Address::default())?;
            // SAFETY: Box fields and initialized Vec allocation stay stable until
            // completion; lengths fit u32; single 80-byte address, no batching.
            let ok = unsafe { (self.api.recv)(self.handle, io.data.as_mut_ptr().cast(), MAX_PACKET as u32,
                &mut io.length, 0, &mut io.address, &mut io.address_length, &mut io.overlapped) };
            if ok == 0 {
                let e = error(ErrorKind::Receive);
                if e.os_code != Some(IO_PENDING) { return self.receive_failure(e); }
            } else { synchronous = true; }
            self.pending = Some(io);
        }
        if !synchronous {
            match self.wait(100, ErrorKind::Receive) {
                Ok(false) => return Ok(Poll::Idle),
                Err(e) => return self.receive_failure(e),
                Ok(true) => (),
            }
        }
        let mut io = self.pending.take().ok_or(CaptureError::new(ErrorKind::Receive, None))?;
        if io.length == 0 || io.length as usize > io.data.len() || io.address_length != 80 {
            return Err(CaptureError::new(ErrorKind::InvalidPacket, None));
        }
        io.data.truncate(io.length as usize);
        let bytes = std::mem::take(&mut io.data);
        Ok(Poll::Packet(Packet { bytes, address: io.address.clone() }))
    }

    pub fn send(&mut self, bytes: &[u8], address: &Address) -> Result<(), CaptureError> {
        if self.mode == Mode::Sniff || self.handle.is_null() || self.pending.is_some()
            || bytes.is_empty() || bytes.len() > MAX_PACKET {
            return Err(CaptureError::new(ErrorKind::Send, None));
        }
        // Copy only for stable async ownership. Never rewrite bytes or address.
        let mut io = Io::new(bytes.to_vec(), address.clone())?;
        debug_assert!(io.data == bytes && io.address == *address, "Phase 2 native byte/address invariant");
        // SAFETY: owned immutable packet/address, stable output length and
        // OVERLAPPED storage retained until completion or quarantine.
        let ok = unsafe { (self.api.send)(self.handle, io.data.as_ptr().cast(), bytes.len() as u32,
            &mut io.length, 0, &io.address, 80, &mut io.overlapped) };
        if ok == 0 {
            let e = error(ErrorKind::Send);
            if e.os_code != Some(IO_PENDING) { return Err(e); }
        }
        self.pending = Some(io);
        if ok == 0 && !self.wait(1000, ErrorKind::Send)? {
            return Err(CaptureError::new(ErrorKind::Send, Some(WAIT_TIMEOUT)));
        }
        let io = self.pending.take().ok_or(CaptureError::new(ErrorKind::Send, None))?;
        if io.length as usize != bytes.len() {
            return Err(CaptureError::new(ErrorKind::Send, None));
        }
        Ok(())
    }

    pub fn shutdown_receive(&mut self) -> Result<(), CaptureError> {
        if self.stopped || self.handle.is_null() { return Ok(()); }
        // SAFETY: valid owned handle; RECV=1 stops new admission but permits drain/send.
        if unsafe { (self.api.shutdown)(self.handle, 1) } == 0 { return Err(error(ErrorKind::Shutdown)); }
        self.stopped = true;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), CaptureError> {
        if self.handle.is_null() { return Ok(()); }
        let mut failure = self.shutdown_receive().err();
        if let Some(io) = self.pending.as_mut() {
            // SAFETY: exact pending OVERLAPPED, alive for cancellation and completion.
            if unsafe { CancelIoEx(self.handle, &mut io.overlapped) } == 0 {
                let e = error(ErrorKind::Shutdown);
                if e.os_code != Some(1168) { failure = Some(e); }
            }
            match self.wait(1000, ErrorKind::Shutdown) {
                Ok(true) => { self.pending.take(); }
                // OPERATION_ABORTED is an expected terminal cancellation result.
                Err(e) if e.os_code == Some(995) => (),
                Err(e) => { failure = Some(e); }
                Ok(false) => { failure = Some(CaptureError::new(ErrorKind::Shutdown, Some(WAIT_TIMEOUT))); }
            }
        }
        if let Some(io) = self.pending.take() {
            // A malfunctioning driver may not complete cancellation. Preserve all
            // kernel-referenced storage/module/handles until process exit instead
            // of an infinite wait or freeing memory still owned by pending I/O.
            std::mem::forget(io);
            std::mem::forget(Rc::clone(&self.api));
            self.handle = ptr::null_mut();
            return Err(failure.unwrap_or(CaptureError::new(ErrorKind::Shutdown, None)));
        }
        // SAFETY: no pending operations remain; handle closed once; library retained.
        if unsafe { (self.api.close)(self.handle) } == 0 { failure = Some(error(ErrorKind::Shutdown)); }
        self.handle = ptr::null_mut();
        failure.map_or(Ok(()), Err)
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        if let Err(e) = self.close() { eprintln!("{e}"); }
    }
}

static STOP: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);
extern "system" fn console_control(kind: u32) -> i32 {
    if kind == 0 || kind == 1 {
        STOP.store(true, Ordering::Release);
        1
    } else { 0 }
}

pub struct ConsoleStop { installed: bool }
impl ConsoleStop {
    pub fn install() -> Result<Self, CaptureError> {
        if INSTALLED.swap(true, Ordering::AcqRel) { return Err(CaptureError::new(ErrorKind::Shutdown, None)); }
        STOP.store(false, Ordering::Release);
        // SAFETY: callback has static lifetime, only accesses static atomics.
        if unsafe { SetConsoleCtrlHandler(Some(console_control), 1) } == 0 {
            let e = error(ErrorKind::Shutdown);
            INSTALLED.store(false, Ordering::Release);
            return Err(e);
        }
        Ok(Self { installed: true })
    }
    pub fn flag(&self) -> &AtomicBool { &STOP }
    pub fn close(&mut self) -> Result<(), CaptureError> {
        if !self.installed { return Ok(()); }
        // SAFETY: same static callback registered above; no invalidated context.
        if unsafe { SetConsoleCtrlHandler(Some(console_control), 0) } == 0 { return Err(error(ErrorKind::Shutdown)); }
        self.installed = false;
        INSTALLED.store(false, Ordering::Release);
        Ok(())
    }
}
impl Drop for ConsoleStop {
    fn drop(&mut self) {
        if let Err(e) = self.close() { eprintln!("{e}"); }
    }
}
