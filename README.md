# unzapret-by-sh1dan — 1.0.5-rc.1

Экспериментальный локальный Windows 10/11 x64 TCP-профиль поверх WinDivert 2.2.
Прямое соединение с сервером сохраняется; VPN/proxy/tunnel не используется.

**Это тестовая сборка исправлений, а не подтверждённый обход Discord Voice.**
Она исправляет неожиданный выбор AutoBypass, ошибочное разрешение UDP по порту,
ложные счётчики dry-run и сообщения диагностики. Стратегии обхода голосового UDP
и QUIC в этой версии недоступны. В комплекте UDP capture выключен.
Работа TCP split зависит от провайдера, доступного SNI и конкретного соединения.

## Проверка у друга

1. Завершить старую консоль через Ctrl+C. Если установлена служба — выполнить
   `dpi-bypass.exe service stop` из старой папки от администратора. Проверить
   `dpi-bypass.exe service status`: служба должна быть Stopped или Not Installed.
2. Распаковать новый ZIP **в отдельную папку**, без переноса старого config.
3. Запустить `start.cmd`. В окне должна отображаться версия `1.0.5-rc.1`,
   `Mode: active` и `Strategy: split-tcp`. Консоль оставлять открытой.
4. Полностью перезапустить Discord/браузер, проверить текст/HTTPS и отдельно voice.
   Сохранить 2–3 строки `[counters]`, сведения о пинге и название провайдера.
5. Остановить через Ctrl+C и сравнить с программой, полностью выключенной.
   Для сравнения capture overhead можно отдельно запустить `start_dry_run.cmd`.
   Во время sniff-теста `modified=0`; `would_modify` обозначает только намерение.

До результата этой проверки новую службу устанавливать не нужно. Старые версии
не поддерживают новый mutex; их нужно остановить вручную. Новый mutex предотвращает
конкуренцию экземпляров новой версии, но не обнаруживает все сторонние WFP-драйверы.

Если voice не работает и при полностью выключенном приложении, эта TCP-сборка
может не изменить ситуацию: отдельный рабочий voice-профиль ещё предстоит реализовать
и испытать. Не добавляйте весь интернет в IP allowlist и не удаляйте exclusions.

## Команды

```powershell
dpi-bypass.exe --version
dpi-bypass.exe start
dpi-bypass.exe start --dry-run
dpi-bypass.exe service status
dpi-bypass.exe service stop
dpi-bypass.exe config show
dpi-bypass.exe strategies
dpi-bypass.exe diagnose
```

`config show` читает реальный `config/default.toml` рядом с executable.
`status` не является live IPC-запросом к другой консоли.
`test` выполняет лишь частичные TLS connectivity probes, не запускает стратегии,
не проверяет сертификаты/полный HTTPS/voice и возвращает код 2 (INCONCLUSIVE).
`test --mock` — только синтетическая демонстрация, не доказательство доступности.
`diagnose` теперь отделяет локальный UDP bind от непроверенной удалённой связности;
значения proxy environment variables скрыты.

`split-tcp` выбирает только SplitTcp. `auto` и неизвестные/выключенные стратегии
отклоняются. Экспериментальные модули UDP остались в исходниках для дальнейшего
аудита, но недоступны через runtime-фабрику профилей этого кандидата.

## Сборка и тесты

Нужен Rust toolchain с linker (на Windows — MSVC Build Tools и Windows SDK).
Проверка выполнена на Rust 1.98.1; заявленный MSRV 1.74 отдельно не проверен.
Первой сборке нужен доступ к Cargo registry или заранее заполненный cache.
Зависимости зафиксированы в Cargo.lock; vendoring в этом checkout не настроен.

```powershell
cargo fmt --all -- --check
cargo build --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked
```

Для offline-сборки при наличии cache добавьте `--offline`.
Нужные локальные файлы драйвера: `WinDivert/WinDivert.dll` и
`WinDivert/WinDivert64.sys` рядом с exe. Приложение их не скачивает.
Наличие/подпись SYS не доказывает, что драйвер разрешён системой конкретного пользователя.

## Ограничения и документы

Нет гарантии нулевого overhead, обхода любого DPI или работы всех приложений.
Нет TLS reassembly/ECH decryption; flow budget ещё не учитывает TCP sequence ranges.
Служба поддерживает SCM start/stop, но её startup readiness и установка в защищённый
каталог требуют дальнейшей проверки; этот кандидат предназначен для foreground-теста.
Нет телеметрии, чтения browser DB/Discord tokens и изменений firewall/Defender.

[Исходный аудит de3ab0f](docs/audit-2026-09-15.md) и
[исправления кандидата](docs/fixes-1.0.5-rc.1.md).
Лицензия приложения MIT; сторонний WinDivert имеет собственные лицензионные условия.
