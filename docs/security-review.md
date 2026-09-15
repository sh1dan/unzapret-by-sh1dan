> Исторический self-review, не сертификат безопасности. Обнаруженные дефекты: [audit-2026-09-15.md](audit-2026-09-15.md); текущие исправления и ограничения: [fixes-1.0.5-rc.1.md](fixes-1.0.5-rc.1.md).

# Security & Privacy Review — unzapret-by-sh1dan

**Date**: 2026-09-14  
**Scope**: `unzapret-by-sh1dan` (Phases 1–10)  
**Repository**: [https://github.com/sh1dan/unzapret-by-sh1dan](https://github.com/sh1dan/unzapret-by-sh1dan)

---

## 1. Memory Safety & Unsafe Code Boundary

- **Core Application Guarantee**: The main crate (`local_dpi_bypass`) strictly enforces `#![forbid(unsafe_code)]`.
- **FFI Boundary**: All Windows Win32 and WinDivert C-ABI interop is strictly quarantined inside `crates/windivert-adapter`:
  - Memory bounds on WinDivert packet buffers are strictly checked against `MAX_PACKET = 65575`.
  - Overlapped asynchronous I/O correctly accounts for transferred byte lengths via `GetOverlappedResult`.
  - SCM pointers and handles are managed using safe RAII wrappers (`ScHandle`, drop handlers) to prevent resource leaks.

---

## 2. Windows Service Security (SCM)

- **CWE-428 Mitigation (Unquoted Search Path)**:
  - All calls to `CreateServiceW` format the binary path using `build_quoted_service_command()`:
    ```text
    "C:\Program Files\Local DPI Bypass\dpi-bypass.exe" service run
    ```
  - Double quotes around the binary path prevent path-interception privilege escalation.
- **Access Control & Privilege Separation**:
  - Service installation and removal require elevated Windows Administrator privileges.
  - Unprivileged attempts return explicit `AccessDenied` errors without modifying system state.
- **Clean Deletion Guarantee**:
  - `service remove` signals `SERVICE_CONTROL_STOP`, waits for process termination, and calls `DeleteService`. No orphaned background processes, scheduled tasks, or persistent registry keys remain.

---

## 3. Network & Traffic Privacy

- **Zero Telemetry / Zero External Dependencies**:
  - No analytics, telemetry, or remote command-and-control servers.
  - The application uses only the standard library and static dependencies (`toml` parser without external network features).
- **Log Privacy Guarantee (`logs/app.log`)**:
  - Logs are strictly limited to lifecycle events (`START`, `STOP`), aggregate counters (`processed`, `reinserted`, `modified`, `errors`, `dropped`), and diagnostic check statuses.
  - **Strictly Forbidden & Audited**:
    - Zero user URLs
    - Zero packet payload data
    - Zero flow-specific IP addresses
    - Zero extracted SNI domain strings
  - Bounded size: maximum 512 KB per file with a single rotation backup (`app.log.1`).

---

## 4. Packet Processing & Fail-Safe Architecture

- **Bounded State**:
  - The flow table is bounded by `max_flows` (default 4096) with automatic idle eviction (`flow_idle_seconds`) and strict initial packet budget (`max_packets_per_flow = 4`).
  - Table saturation degrades gracefully to byte-exact pass-through rather than dropping packets.
- **Checksum Invariance**:
  - Any segmented TCP packet has its RFC 1071 internet checksum and IPv4 header checksum recalculated with zero error tolerance.
- **RTP Media Unchanged Guarantee**:
  - Discord voice RTP streams on UDP ports 50001–50005 are classified as `media unchanged` and pass through unmodified to guarantee zero audio distortion.

---

## 5. Read-Only Diagnostics

- `dpi-bypass diagnose` executes strictly read-only checks (token elevation, file existence, DNS resolution, and TCP/TLS handshake responses).
- Never modifies Windows Firewall rules, network interface settings, or DNS servers.
- Features not active or supported on the host return `Unsupported`/`NotRun`, never fabricated `Ok`.
