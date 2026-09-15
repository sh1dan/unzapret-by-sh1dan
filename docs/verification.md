> Актуальные результаты кандидата 1.0.5-rc.1: [fixes-1.0.5-rc.1.md](fixes-1.0.5-rc.1.md). Ниже сохранена история прежних этапов.

# Проверка Phase 1

Дата: 2026-09-14. Исходная рабочая папка была пустой.

Попытки выполнить `cargo build --offline --all-targets` и `cargo test --offline`
завершились кодом 1: PowerShell не нашёл cargo. rustc/cargo отсутствуют в PATH
и стандартном пользовательском каталоге .cargo/bin. WSL inventory также недоступен
(E_ACCESSDENIED), поэтому он не использован как альтернативная среда.
Компилятор и SDK автоматически не устанавливались.

**Сборка и Rust-тесты не подтверждены.** CI workflow добавлен, но не запускался.
После установки toolchain выполнить команды из README. Не считать этот каркас
готовым Windows executable до успешной сборки и проверки.

Добавлены 7 контрактных тестов: bypass для Exclude/Unknown/NoMatch, запрет обработки
позднего payload, dry-run suppression, unavailable engine, unavailable service
install/remove/start/stop/status, CLI reserved operations, безопасные defaults/filter.
Настоящих packet/checksum/config-parser/SCM integration tests пока нет.

Статическая проверка Python 3.14.4 / tomllib завершилась успешно (exit code 0):
Cargo.toml и default.toml синтаксически корректны; все пути модулей, binary/lib и
allowlist-файлов существуют; пути preset-файлов остаются внутри config; пример
использует dry-run, запрещает payload logging и выбирает enabled pass-through.
В tests/contracts.rs присутствуют 7 тестов. Эта проверка не доказывает корректность
Rust type checking или Windows runtime и не является запуском этих 7 тестов.
