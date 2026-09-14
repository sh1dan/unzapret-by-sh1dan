# unzapret-by-sh1dan — Local DPI Bypass for Windows

[![CI & Release](https://github.com/sh1dan/unzapret-by-sh1dan/actions/workflows/ci.yml/badge.svg)](https://github.com/sh1dan/unzapret-by-sh1dan/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/sh1dan/unzapret-by-sh1dan?color=brightgreen)](https://github.com/sh1dan/unzapret-by-sh1dan/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows 10/11 x64](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20x64-blue.svg)](https://github.com/sh1dan/unzapret-by-sh1dan)

**unzapret-by-sh1dan** — автономная, быстрая и безопасная программа для Windows 10/11 на языке **Rust** для обхода блокировок и замедлений (DPI) с использованием драйвера WinDivert 2.2.

> [!TIP]
> **Прямое соединение без VPN и серверов-посредников**: программа работает локально на вашем компьютере (`ваш ПК -> целевой сайт`). Скорость интернета и пинг не режутся, ваши пароли и данные не проходят через чужие серверы, телеметрии нет.

---

## 🚀 Быстрый старт (для обычных пользователей)

Вам **не нужно** ничего компилировать или устанавливать среды разработки:

1. **Скачайте готовый архив**:
   👉 **[Скачать unzapret-by-sh1dan (ZIP архив)](https://github.com/sh1dan/unzapret-by-sh1dan/releases/latest)**
2. **Распакуйте архив** в любую удобную папку (например, `C:\unzapret` или на Рабочий стол).
3. **Запустите обход**:
   - Дважды кликните по **`start.cmd`** (скрипт сам запросит права Администратора).
   - В открывшемся окне отобразится статус работы.
   - Откройте браузер или приложения: **YouTube (4K), Discord (включая голосовые каналы), Twitch, Telegram** теперь работают без блокировок!
   - Чтобы закрыть программу — просто нажмите `Ctrl + C` или закройте окно консоли.

> [!NOTE]
> **Хотите, чтобы программа работала незаметно в фоне и запускалась вместе с Windows?**  
> Кликните правой кнопкой мыши по **`service_install.cmd`** и запустите от имени Администратора.  
> Для полного удаления службы используйте **`service_remove.cmd`**.

---

## 🎯 Что работает «из коробки»

- 📺 **YouTube**: видео открываются моментально в исходном качестве (1080p, 2K, 4K, 60fps).
- 💬 **Discord**: работает текст, картинки, медиа и **Discord Voice** (голосовые каналы и звонки благодаря специальному профилю для STUN/RTP портов).
- 🎮 **Twitch**: прямые трансляции в максимальном качестве без буферизации.
- ✈️ **Telegram**: веб-клиент и десктопное приложение.
- 🌐 **Любые другие сайты**: просто допишите нужный домен в файл `config/domains.txt`.

---

## 📂 Готовые скрипты управления (в один клик)

В папке программы подготовлены удобные скрипты с автоматическим запросом прав администратора (UAC):

| Скрипт | Что делает |
|---|---|
| **`start.cmd`** | Запуск обхода в окне консоли (остановка: `Ctrl+C` или закрытие окна). |
| **`service_install.cmd`** | Установка службы Windows (работает в фоне, автозапуск с Windows). |
| **`service_remove.cmd`** | Полная остановка и удаление службы из системы. |
| **`service_status.cmd`** | Проверка текущего статуса службы (`Running` / `Stopped`). |
| **`diagnose.cmd`** | Автоматическая проверка системы (права, драйвер, DNS, доступность сервисов). |
| **`test.cmd`** | Экспресс-тест доступности YouTube, Discord, Twitch и Telegram. |
| **`logs.cmd`** | Просмотр последних событий и сообщений программы. |
| **`start_dry_run.cmd`** | Безопасный тестовый режим (сниффер без изменения пакетов). |

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
