# Исправления 1.0.5-rc.1 (2026-09-15)

Основа: de3ab0f / локальный v1.0.4. Кандидат для foreground-проверки.
Подтверждённого работающего Discord Voice обхода в этой сборке нет.

## Изменения

- Общая фабрика CLI/SCM: split-tcp означает SplitTcp; auto/неизвестные имена
  отклоняются. Loader проверяет enabled у выбранного профиля. Экспериментальный
  AutoBypass сохранён как исходный модуль для аудита, но runtime его не выбирает.
- STUN/порт больше не разрешают неизвестное назначение. Domain exclusions
  защищают TCP и UDP. Пустые пресеты не включают неявные порты 80/443.
- Комплектный конфиг отключает голосовой preset и UDP/443: TCP-профиль
  не должен добавлять capture overhead голосу и QUIC без поддерживаемой стратегии.
- Empty TCP SYN/ACK не расходуют payload budget. Splitter отказывается от
  SYN/FIN/RST/URG с payload. modified учитывает завершённую отправку обеих частей;
  dry-run увеличивает только would_modify. Вывод содержит eligible/send/receive errors.
- Ошибка WinDivert не маскируется fallback-конфигурацией Phase 2.
- Новый глобальный именованный mutex не допускает двух capture экземпляров
  новой версии, включая console/service. Не требует ожидания, исчезает с последним
  handle. Его можно заблокировать локальным процессом; это availability-ограничение,
  а не граница защиты от локального злоумышленника. Старые версии mutex не создают.
- Exit code службы теперь сигнализирует runner failure (1066 / service-specific 1).
  Полная startup readiness и тест установки/удаления SCM в VM ещё не выполнены.
- Voice diagnose делает только local bind, возвращает NotRun без hardcoded UDP probe.
  TLS diagnostics явно сообщает о непроверенных certificate/HTTPS/voice.
  Значения proxy environment variables не печатаются.
- test больше не выдаёт прямые probes за подбор стратегий: connectivity-only,
  INCONCLUSIVE и код 2. config show читает настоящий config возле exe.
- CMD проверяет admin token вместо зависимости от net session/LanmanServer.
  Путь для UAC передаётся через environment variable, без вставки пути в PowerShell-код.
- CI восстановлен для Windows и Ubuntu; добавлены fmt/clippy; release staging
  исключает пользовательские logs и пересчитывает checksum manifest после сборки.
- Cargo/Rust версия кандидата 1.0.5-rc.1; форматирование нормализовано rustfmt.

## Проверки

Среда Windows x64, Rust/Cargo 1.98.1, offline cache.

- cargo test --workspace --locked --offline: **116 passed**, 0 failed.
- cargo fmt --all -- --check: успешно.
- cargo clippy --workspace --all-targets --locked --offline -- -D warnings: успешно.
- cargo build --release --locked --offline: успешно.
- Mutex conflict/release проверен настоящими Win32 вызовами с отдельным test name.
- Новые regressions: точный выбор профиля, запрет port-only/STUN grant, UDP exclusions,
  отсутствие fallback capture ports, пакетные конфиги, SYN/ACK budget, control flags.
- Существующий тест, требовавший fake для port-only STUN, исправлен на исходный
  allowlist-контракт: один неизменённый пакет, без fake.

Toolchain всё ещё печатает `could not canonicalize path C:\Users\yanry`.
Это предупреждение среды; перечисленные команды завершились успешно.
Linux job добавлен, но на этом компьютере не запускался. MSRV 1.74 не проверен.
Живой WinDivert capture, обход сети друга, UAC и SCM installation в VM не проверялись.

## Что остаётся

Отдельные voice/QUIC стратегии, end-to-end HTTPS/voice tester, TCP sequence-aware
flow tracking, TLS reassembly/ECH support, полный review FFI/SCM и нагрузочные
замеры остаются работой следующих итераций. Производительность и эффективность
TCP split зависят от сети; эта сборка не гарантирует восстановление голоса.
Первым шагом проверяйте отсутствие регрессии с программой выключенной и включённой.

Порядок запуска — README.md и CHECK-FIRST.txt внутри ZIP. Старую копию/службу
нужно остановить, архив распаковать отдельно и не переносить прежнюю конфигурацию.
Никакие службы, firewall/Defender settings и GitHub releases при создании кандидата
не изменялись. Архив и исправления подготовлены локально.

Win32 mutex semantics: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw
