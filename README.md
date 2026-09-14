# unzapret-by-sh1dan — Local DPI Bypass for Windows

[![CI](https://github.com/sh1dan/unzapret-by-sh1dan/actions/workflows/ci.yml/badge.svg)](https://github.com/sh1dan/unzapret-by-sh1dan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**unzapret-by-sh1dan** — автономное, локальное Windows 10/11 приложение на языке **Rust** для обхода блокировок DPI (Deep Packet Inspection) с использованием драйвера WinDivert 2.2.

**Репозиторий**: [https://github.com/sh1dan/unzapret-by-sh1dan](https://github.com/sh1dan/unzapret-by-sh1dan)

> [!NOTE]
> **Прямое соединение без VPN и Proxy**: приложение работает исключительно локально на уровне сетевого стека Windows (`client -> target server`). Нет внешних VPN-серверов, туннелей, удалённого управления или сбора телеметрии.

---

## Ключевые возможности

- 🚀 **100% Memory Safe**: основной движок скомпилирован со строгим `#![forbid(unsafe_code)]`. Все небезопасные FFI-вызовы Win32 и WinDivert изолированы в минимальном адаптере `windivert-adapter`.
- ⚡ **TCP Segmentation (`split-tcp`)**: интеллектуальное разбиение начального TLS ClientHello пакета на сегменты со строгим пересчётом контрольных сумм TCP/IPv4 по RFC 1071.
- 🎯 **Поддерживаемые сервисы (пресеты из коробки)**:
  - **YouTube**: HTTPS и видеотрафик (`googlevideo.com`, `youtube.com`).
  - **Discord**: веб/клиент HTTPS + **Discord Voice** (STUN NAT discovery + гарантия `media unchanged` для RTP аудиопотока).
  - **Twitch**: прямые трансляции и чат (`twitch.tv`, `ttvnw.net`).
  - **Telegram**: веб-версии и API (`t.me`, `telegram.org`).
  - **Custom**: пользовательские домены и CIDR-подсети в `config/domains.txt` и `config/ips.txt`.
- 🛡️ **Служба Windows (SCM)**: возможность работы в качестве фоновой автозапускаемой службы (`LocalDpiBypass`) с защитой от уязвимостей unquoted path (CWE-428).
- 🔍 **Встроенный диагностический комплекс (`dpi-bypass diagnose`)**: read-only проверка прав администратора, драйверов, DNS dual-stack, доступности YouTube/Discord, конфликтующих программ и состояния службы.
- 🧪 **Автоматический тестер стратегий (`dpi-bypass test`)**: последовательное тестирование кандидатов обхода с замером задержки в миллисекундах и честной атрибуцией.
- 🔒 **Строгая приватность логов (`logs/app.log`)**: ротируемый лог (до 512 КБ). Категорически запрещена запись raw-пакетов, полезной нагрузки, SNI, IP пользователей или URL.

---

## Быстрый запуск (Готовые скрипты в папке `run/`)

Для конечных пользователей в каталоге `run/` подготовлены удобные скрипты с автоматическим запросом прав администратора (UAC):

| Скрипт | Назначение |
|---|---|
| **`start.cmd`** | Запуск обхода в окне консоли (Active Capture & Bypass). Остановка: `Ctrl+C`. |
| **`service_install.cmd`** | Установка и запуск фоновой службы Windows (автозапуск при включении ПК). |
| **`service_remove.cmd`** | Остановка и полное удаление службы Windows из системы. |
| **`service_status.cmd`** | Проверка текущего состояния службы Windows (`Running`, `Stopped`, `Not Installed`). |
| **`test.cmd`** | Запуск автоматического тестирования стратегий обхода target-серверов. |
| **`diagnose.cmd`** | Запуск 10-точечной read-only диагностики готовности системы. |
| **`logs.cmd`** | Просмотр последних записей журнала событий. |
| **`start_dry_run.cmd`** | Безопасный режим сниффера без модификации и реинжекции пакетов. |

---

## Использование через командную строку (CLI)

```powershell
# Запуск движка обхода (требуются права администратора)
dpi-bypass.exe start

# Запуск в безопасном режиме сниффера (без изменения пакетов)
dpi-bypass.exe start --dry-run

# Тестирование стратегий обхода (YouTube, Discord, Twitch, Telegram)
dpi-bypass.exe test

# Управление службой Windows
dpi-bypass.exe service install   # Установка автозапускаемой службы
dpi-bypass.exe service start     # Запуск службы
dpi-bypass.exe service status    # Проверка статуса службы
dpi-bypass.exe service stop      # Остановка службы
dpi-bypass.exe service remove    # Удаление службы

# Диагностика и логи
dpi-bypass.exe diagnose          # Read-only диагностика системы
dpi-bypass.exe logs              # Просмотр последних логов

# Информационные команды
dpi-bypass.exe status            # Текущий статус движка
dpi-bypass.exe strategies        # Список поддерживаемых стратегий
dpi-bypass.exe config show       # Просмотр примера конфигурации
dpi-bypass.exe help              # Справка по командам
```

---

## Структура дистрибутива (`run/`)

```text
run/
├── dpi-bypass.exe          # Релизный бинарник (LTO, strip, overflow checks)
├── WinDivert/
│   ├── WinDivert.dll       # Пользовательская библиотека WinDivert 2.2
│   └── WinDivert64.sys     # Драйвер перехвата пакетов x86_64
├── config/
│   ├── default.toml        # Основная строгая конфигурация
│   ├── phase2.toml         # Конфигурация перехватываемых IP и портов
│   ├── domains.txt         # Пользовательские разрешённые домены
│   ├── ips.txt             # Пользовательские разрешённые IP / CIDR
│   ├── exclude-domains.txt # Исключённые домены (всегда pass-through)
│   ├── exclude-ips.txt     # Исключённые IP / CIDR
│   └── presets/            # Готовые списки доменов и IP
│       ├── youtube/
│       ├── discord/
│       ├── discord-voice/
│       ├── twitch/
│       └── telegram/
├── logs/                   # Ротируемые журналы событий (app.log)
├── SHA256SUMS.txt          # Контрольные суммы файлов дистрибутива
└── *.cmd                   # Скрипты управления в один клик
```

---

## Сборка из исходников

Для сборки требуются **Rust >= 1.74** (MSVC toolchain на Windows) и **Windows SDK**:

```powershell
# Сборка проекта без доступа к сети (все зависимости зафиксированы в vendor)
cargo build --release --offline

# Запуск всех 100+ unit- и контрактных тестов
cargo test --offline
cargo test -p windivert-adapter --offline
```

---

## Безопасность и модель угроз

- **CWE-428 (Unquoted Service Path)**: путь к исполняемому файлу службы всегда строго экранируется двойными кавычками (`"C:\path\to\dpi-bypass.exe" service run`).
- **Чистое удаление**: при удалении службы (`service remove`) процесс завершается и удаляется из SCM. Никаких неудаляемых драйверов, задач планировщика или ключей автозагрузки в реестре.
- **Fail-Safe**: при переполнении очереди потоков или неизвестных протоколах пакеты передаются неизменёнными без сбоя соединений.
- **Аудит безопасности**: подробности см. в [docs/security-review.md](docs/security-review.md) и [docs/threat-model.md](docs/threat-model.md).

---

## Лицензия

Проект распространяется под лицензией [MIT](LICENSE).
Оригинальный драйвер WinDivert лицензирован под GNU LGPLv3 / GPLv2.
