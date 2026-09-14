# Phase 2 — полный снимок файлов

Все новые и изменённые файлы Phase 2. Сборка Cargo не запускалась (Cargo недоступен локально);
offline тесты валидируют contracts, parser, Phase2Config и PassThroughEngine через mock capture.

## Перечень

- `.github/workflows/ci.yml` — обновлён (Phase 2 contracts, crate tests)
- `Cargo.toml` — workspace + toml dep
- `crates/windivert-adapter/Cargo.toml`
- `crates/windivert-adapter/src/lib.rs` — safe wrapper, unsupported stub, path validation
- `crates/windivert-adapter/src/ffi.rs` — единственная unsafe граница: WinDivert 2.2 FFI
- `config/phase2.toml` — пример runtime конфига (disabled)
- `src/CLI/mod.rs` — Phase 2 HELP + реализованный `start [--dry-run]`
- `src/Core/parser.rs` — bounds-checked IPv4/v6 + TCP/UDP parser
- `src/Core/phase2_config.rs` — TOML parse + WinDivert filter expression builder
- `src/Core/pipeline.rs` — PassThroughEngine<C> с drain/shutdown/counters
- `src/PacketCapture/mod.rs` — PacketCapture trait, CapturedPacket, ReceiveEvent
- `src/PacketCapture/windivert.rs` — WinDivertCapture адаптер
- `tests/contracts.rs` — Phase 1 + Phase 2 offline тесты

## SHA-256 хеши

| Файл | SHA-256 |
|---|---|
| `.github/workflows/ci.yml` | `bbf2d4bbb6a7a9ea1f964cd412a16e69db0a4f911102829fb8fb6b1af4511338` |
| `Cargo.toml` | `b000939985444d0a04d7568e9e199a9dd52ab9234132c56eafce20782e60565b` |
| `crates/windivert-adapter/Cargo.toml` | `a46c9f0badfb6965702e775e1a5a53c687bf7c9fa28b9c1e5ae087239210995c` |
| `crates/windivert-adapter/src/lib.rs` | `73e008904f78e5aa25f46bbbf1892d63495e17e8b0c6b90c8abfddc2003b264f` |
| `crates/windivert-adapter/src/ffi.rs` | `34a0d2efd733936ba876c35ff32a1ad7ff7582882e9706ea76dab53426286c0f` |
| `config/phase2.toml` | `f585a5265da4dd1c24fe6ad016fee8420fecb9853675d91df67926b3dea6ccc6` |
| `src/CLI/mod.rs` | `c6168bdc46a9282c0e2849d838815109d5807f680b68a389ff717a79fcfa611b` |
| `src/Core/parser.rs` | `1f869d9150434d5b573b0bf1097c204064afc627e6a702f3100e928bb3bd8bff` |
| `src/Core/phase2_config.rs` | `6619f5a11c931d4fd8adc72c835a2f8835973701196bcd64a23b7089a519b702` |
| `src/Core/pipeline.rs` | `55e2df1fb2ffb084212b1c5d2b2b09d1b5b6cfed05347f8794b430b590aea0e1` |
| `src/PacketCapture/mod.rs` | `99e6fb66af705293a9609d772691e2593570137904aa7c2cbcf826b902a468b8` |
| `src/PacketCapture/windivert.rs` | `ab6bce3ca6ad4e46fb4ec46a6c23e20b74ad6522a0c3c2e1e4e84dffa1406355` |
| `tests/contracts.rs` | `e074f34cc2ed7319fce82d967c516a97d2f59d02e8fe75ad72172e52a60a8321` |

## Архитектурные решения Phase 2

**FFI-crate**: `crates/windivert-adapter` - единственная `unsafe` граница.
Основной crate: `#![forbid(unsafe_code)]`. DLL из validated_file (без symlink escape).
Файлы DLL/SYS открываются с FILE_SHARE_READ lock — защита от замены во время работы.

**Parser**: bounds-checked, без паник, без логирования входных байтов. IPv4 фрагменты,
неизвестные протоколы — Unsupported (pass-through). Checksum не проверяется.

**Phase2Config**: строгий TOML (ровно 4 ключа, max 32 IP/ports, no port 0, no
loopback/multicast/link-local). Filter expression только если enabled=true + IP + ports.

**Pipeline**: PassThroughEngine<C: PacketCapture> generic, тестируется через mock.
Shutdown: stop_flag -> shutdown_receive() -> drain (max 3s) -> End -> Ok(counters).

**CLI start**: единственная команда с побочными эффектами. На non-Windows/без прав
возвращает UnsupportedPlatform или AccessDenied с exit code 1.

## Ограничения

- WinDivert DLL/SYS не включены; разместить рядом с exe в WinDivert/
- Checksum не пересчитывается (pass-through, no modification)
- Flow state, allowlist, domain filtering — Phase 3
- SCM service — Phase 8
