# Этапы и критерии приёмки

Phase 2 — текущая реализация: WinDivert capture/inspect/reinject, byte-exact pass-through, offline parser/config тесты.
После каждого этапа: build, tests, полный список изменений, решения и ограничения.

| Phase | Работа | Обязательная проверка |
|---|---|---|
| ✓ 1 | Контракты, CLI skeleton, схема config, threat model | Cargo build/test, honest unavailable states, gate tests |
| ✓ 2 | WinDivert capture/inspect/reinject, sniff dry-run, offline parser/config тесты | Windows admin lab, byte-exact pass-through, shutdown/drain/send errors |
| ✓ 3 | TOML/TXT parser, allow/exclude, bounded flow state | Config unknown keys/paths, domain boundaries, IPv4/v6 CIDR, exclude priority |
| ✓ 4 | Первая TCP segmentation strategy | TCP seq/flags/options/retransmit, checksum vectors, server receives same bytes |
| ✓ 5 | TLS metadata и QUIC Initial support | Truncated TLS, IPv6 ext headers, QUIC varint/version corpus; HTTPS/QUIC отдельно |
| ✓ 6 | Discord HTTPS и voice/STUN профиль | STUN malformed/length tests, explicit ports/IPs, media unchanged |
| ✓ 7 | Последовательный strategy tester | Timeouts, certificate errors, attribution, profile restore, no competing handles |
| ✓ 8 | SCM install/start/stop/remove | Windows VM integration: quoted path, ACL, reboot, idempotence, pending delete |
| ✓ 9 | Read-only diagnostics и counters/logging | Proxy/VPN/filter cases, Unsupported states, sanitized bounded logs |
| ✓ 10 | Release packaging и security review | Windows 10/11 clean VM, dependency license/hash/signature, complete uninstall |

Phase 1 tests являются контрактными; они **не заменяют** packet-parser, checksum,
TOML parser или реальный service install/remove suite. Эти реализации ещё отсутствуют.
Дальнейшие unit tests: IPv4 lengths/fragments, IPv6 extension bounds, TCP data offset,
UDP length, malformed inputs на каждой границе, checksum odd lengths и pseudoheaders,
TLS nested length mismatch, QUIC varint truncation, STUN padding и типы.
Excluded traffic проверяется byte-for-byte на реальном pipeline перед release.

Reorder, TLS record rewriting, decoy и UDP desync — кандидаты с отдельными критериями;
не обещается, что каждый можно сделать безопасным и полезным для любого провайдера.
Неподтверждённая стратегия остаётся disabled/unsupported.

