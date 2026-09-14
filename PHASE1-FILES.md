# Phase 1 — полный снимок файлов

Все созданные исходные файлы приведены полностью, без сокращений.
Сам этот сводный документ не включён в себя.
Сборка и Rust-тесты не запускались успешно: Cargo отсутствует.

## Перечень

- `.github/workflows/ci.yml`
- `.gitignore`
- `Cargo.toml`
- `config/default.toml`
- `config/domains.txt`
- `config/exclude-domains.txt`
- `config/exclude-ips.txt`
- `config/ips.txt`
- `config/presets/discord/domains.txt`
- `config/presets/discord-voice/domains.txt`
- `config/presets/discord-voice/ips.txt`
- `config/presets/youtube/domains.txt`
- `docs/architecture.md`
- `docs/roadmap.md`
- `docs/threat-model.md`
- `docs/verification.md`
- `LICENSE`
- `README.md`
- `src/CLI/main.rs`
- `src/CLI/mod.rs`
- `src/Core/config.rs`
- `src/Core/mod.rs`
- `src/Diagnostics/mod.rs`
- `src/Filtering/mod.rs`
- `src/lib.rs`
- `src/PacketCapture/mod.rs`
- `src/Service/mod.rs`
- `src/Strategies/mod.rs`
- `tests/contracts.rs`

## .github/workflows/ci.yml

SHA-256: `95f5f8ca9c088ce7d769b4b9980cf360d1622a76b4f7579c02f92360ae717273`

````
name: Phase 1 contracts
on: [push, pull_request, workflow_dispatch]
permissions:
  contents: read
jobs:
  test:
    strategy:
      matrix:
        os: [windows-latest, ubuntu-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - name: Build offline (no third-party crates)
        run: cargo build --offline --all-targets
      - name: Contract tests
        run: cargo test --offline
      - name: CLI smoke test
        run: cargo run --offline -- status
````

## .gitignore

SHA-256: `ed3c48c2e8c7ca04ba9147236bb529d04bf678555165ef6ce71b1bd73f2c5c7f`

````
/target/
/logs/
/vendor/WinDivert/
*.pdb

````

## Cargo.toml

SHA-256: `eee385d0e11c99d2f6c222181039b6cb5333cfae774c010f762ebd67250c7ebe`

````
[package]
name = "local-dpi-bypass"
version = "0.1.0"
edition = "2021"
rust-version = "1.74"
license = "MIT"
description = "Local Windows packet engine: Phase 1 architecture and contracts"
publish = false

[lib]
name = "local_dpi_bypass"
path = "src/lib.rs"

[[bin]]
name = "dpi-bypass"
path = "src/CLI/main.rs"

[profile.release]
overflow-checks = true
lto = true
codegen-units = 1

````

## config/default.toml

SHA-256: `d287a72795657d45ba0d8a0a7097017f37dde633924c6b95291be5552737195a`

````
# Phase 1 schema proposal. No runtime TOML loader exists yet.
schema_version = 1

[engine]
dry_run = true
max_flows = 4096
flow_idle_seconds = 30
max_initial_bytes = 16384
max_packets_per_flow = 4

[targets.youtube]
enabled = true
domains_file = "presets/youtube/domains.txt"
ips_file = "ips.txt"
tcp_ports = [443]
udp_ports = [443]

[targets.discord]
enabled = true
domains_file = "presets/discord/domains.txt"
ips_file = "ips.txt"
tcp_ports = [443]
udp_ports = []

[targets.discord_voice]
# No blanket UDP capture. Populate reviewed IPs/ports before enabling.
enabled = false
domains_file = "presets/discord-voice/domains.txt"
ips_file = "presets/discord-voice/ips.txt"
tcp_ports = []
udp_ports = []

[targets.custom]
enabled = false
domains_file = "domains.txt"
ips_file = "ips.txt"
tcp_ports = [443]
udp_ports = []

[filters]
exclude_domains_file = "exclude-domains.txt"
exclude_ips_file = "exclude-ips.txt"
unknown_action = "pass-through"

[strategy]
name = "pass-through"

[strategies.pass-through]
enabled = true

[strategies.split-tcp]
enabled = false

[strategies.split-tls]
enabled = false

[strategies.reorder]
enabled = false

[strategies.decoy]
enabled = false

[strategies.quic]
enabled = false

[strategies.stun]
enabled = false

[logging]
level = "info"
packet_payload_logging = false
path = "logs/app.log"
max_bytes = 1048576
retained_files = 3

````

## config/domains.txt

SHA-256: `331a48d65bacaa18d1422a87489643bf8a6382a63d783134e370a0de3db9b521`

````
# Custom preset. One exact ASCII hostname or leading-dot suffix per line.
# Empty means no domain targets; never wildcard all destinations.
````

## config/exclude-domains.txt

SHA-256: `de93b6ad849e4f249a79b7c1b2bfd21556fdb265e273f0ac6cfe86117f6db3cc`

````
# Global exclusions override every domain and IP grant.
````

## config/exclude-ips.txt

SHA-256: `951bcd51ca433168d8bff5c084b11e1c361d58292b6f06528ada8a78527060b4`

````
# Global IP/CIDR exclusions override every preset and strategy.
````

## config/ips.txt

SHA-256: `89802b0b7b99d62d97a9c7338fbb56e16ed993d92222930c94869f5cfcfd6634`

````
# Explicit shared IP/CIDR allowlist. Empty by default.
# IP grants apply only inside enabled presets and their configured ports.
````

## config/presets/discord/domains.txt

SHA-256: `f92d30c37479e1c2a4614420f81531e683de8c40212319b7647da0ceada932e1`

````
discord.com
.discord.com
.discord.gg
.discordapp.com
.discordapp.net
````

## config/presets/discord-voice/domains.txt

SHA-256: `7c23c1a6a3ccda64bcb553ae13f357e7bb777ae2902ef08f9cc0000e432fde6c`

````
# No static voice destinations assumed. Review discovered endpoints explicitly.
````

## config/presets/discord-voice/ips.txt

SHA-256: `bc2107baa6a7b3530cdfb8e1b9b45c976ba0c53b84f0eedf828c96e3258eda59`

````
# Populate explicit voice destination IPs/CIDRs and UDP ports before enabling.

````

## config/presets/youtube/domains.txt

SHA-256: `43573407d825c6542168764c524b18d847d0d831742a40f5e8985016bb3a5b9e`

````
www.youtube.com
.youtube.com
.googlevideo.com
.ytimg.com
````

## docs/architecture.md

SHA-256: `41090fae0fcdd625f39bed23b4ea26e8df65648241ab5aaf6232a7ec55a220fc`

````
# Архитектура Phase 1

## Граница текущей реализации

Phase 1 определяет контракты и безопасные заглушки. Нет packet parser, DNS resolver,
TOML loader, flow table, checksum реализации, WinDivert FFI или SCM FFI.
`PassThrough` возвращает решение без копирования/изменения байтов; admission gate
не вызывает стратегию для Exclude, NoMatch, Unknown и не начального payload.
Тестовый SplitTcp проверяет только контракт планирования, не отправку пакетов.

## Поток данных будущего engine

```text
CLI / явная команда установки -> SCM -> PacketEngine
                                      |
                                  PacketCapture
                                      |
  outbound candidate -> bounded parse -> exclusion/allowlist -> flow budget
                                      |
                             Strategy: plan only
                                      |
                      validate -> checksum -> ordered send
```

Неизвестный/неподдержанный/исключённый пакет возвращается неизменённым вместе
с исходными WinDivert address flags. Ошибка парсинга не разрешает стратегию.
Конфигурация полностью проверяется до открытия capture handle. При перегрузке
новые потоки не модифицируются. Нельзя обещать абсолютный fail-open: сбой процесса,
переполнение очереди или ошибка reinjection могут терять пакеты.

`PacketEngine::run(mode, stop)` управляет lifetime capture и возвращает счётчики
либо типизированную ошибку. `stop` — AtomicBool, период ожидания receive должен быть
ограничен или прерван shutdown. Остановка: shutdown receive, drain неизменённых
пакетов, close. Отдельные send errors считаются и завершают работу при устойчивом
сбое; бесконечного retry и повторной отправки уже отправленной части split нет.

`PacketCapture` сохраняет opaque native metadata типом Address. WinDivert адаптер
в дальнейшем размещается в отдельном crate с минимальным проверяемым unsafe FFI;
основной crate запрещает unsafe. Неизменённый пакет не требует произвольной
перезаписи checksum; изменённый требует корректных TCP/UDP pseudo-header checksums
для IPv4/IPv6, IPv4 header checksum и согласованных offload flags.

WinDivert NETWORK работает с локальными исходящими пакетами; forward, loopback,
impostor и нерелевантные порты исключаются. Phase 2 использует только явно заданные
тестовые IP/порты. Позднее доменный режим требует ограниченного просмотра кандидатов
TCP/443 для SNI: захват кандидата не означает разрешение на изменение. Точный
capture expression формируется только из проверенных адресов/портов.

Dry-run будет использовать SNIFF + RECV_ONLY: исходные пакеты идут самостоятельно,
копии анализируются и никогда не reinject. Active pass-through Phase 2, напротив,
должен действительно выполнять capture -> inspect -> reinject.

## Parser, flow state, классификация

Все wire reads проверяют длины до доступа, арифметика checked. Парсеры возвращают
Valid / Unsupported / Malformed, без паник и без логирования входных байтов.
Фрагменты IPv4, неизвестные IPv6 extension chains и сложная reassembly первоначально
Unsupported и пропускаются. TCP options, sequence wrap, MTU и retransmissions
учитываются до разрешения split. Потоки определяются адресами, портами, транспортом
и направлением; бюджет привязан к начальным диапазонам TCP sequence, а не к первым
произвольным пакетам. Retransmissions не должны бесконечно активировать обработку.

TLS ClientHello: доступны только открытые метаданные, включая SNI, если он видим.
ECH, неполный ClientHello и отсутствующий SNI не являются доказательством домена.
Ограниченный буфер reassembly: максимум 16 KiB на поток, 4096 потоков, idle 30 s,
до 4 начальных payload-пакетов. Это целевые лимиты, пока не runtime гарантии.

QUIC Initial: в первой реализации только long-header/version/DCID/SCID/length
с bounds checks. Одного QUIC header недостаточно для определения домена.
Initial deprotection и извлечение CRYPTO не планируются в Phase 1; пользовательский
TLS трафик не расшифровывается. UDP/443 обрабатывается лишь при независимом явном
IP grant и известной версии, иначе pass-through. Успех HTTPS не доказывает QUIC.

STUN: будущий parser проверяет framing, magic cookie, длины и тип сообщения.
STUN-подобные байты сами по себе не разрешают обработку. RTP/RTCP/media пакеты
не модифицируются; Discord voice выключен до явных IP/port allowlist и испытаний.

## Allowlist и исключения

Preset ограничивает протоколы и порты. Доменный grant действует только на flow с
проверенным открытым SNI. DNS ответы не превращаются автоматически в IP grant:
общий CDN адрес может обслуживать посторонний домен. Явный ips.txt — разрешение
на адрес целиком в пределах preset ports; этот эффект нужно показать пользователю.

Порядок: валидность/поддержка -> exclude IP -> exclude domain -> preset protocol/port
-> explicit IP или видимый domain grant. Exclude имеет приоритет над любым Allow.
Если настроены domain exclusions, но домен установить невозможно, модификация
не разрешается даже по IP: исключение иначе нельзя гарантировать. При превышении
лимитов классификация Unknown; это пропуск без изменения.

Формат TXT: комментарий начинается с #; пустые строки пропускаются. Домены ASCII,
case-insensitive, trailing dot нормализуется; Unicode требует явного punycode.
`example.com` — точный host. `.example.com` — apex и поддомены только по границе
label, не `notexample.com`. IP — IPv4/IPv6 и CIDR с проверкой prefix length.
Синтаксические ошибки блокируют запуск, пустые списки ничего не разрешают.

## Стратегии

`Strategy::matches(PacketContext)` и `process(PacketContext) -> ProcessResult` —
статически подключаемые реализации. Загрузка пользовательских DLL не предусмотрена.
Обязательный gate и flow budget находятся вне стратегии. Стратегия возвращает план;
engine повторно проверяет offset/length, TCP flags, размеры, sequence, checksums.
Первая модификация — TCP segmentation исходных байтов без изменения TLS records.
Изменение TLS record framing — отдельный эксперимент, не синоним TCP split.

Reorder и decoy не гарантируют сохранность соединения. Их интерфейс и конфигурационные
флаги зарезервированы, реализации отсутствуют. До изолированных испытаний никакие
fake packets, TTL/checksum tricks или UDP mutations не включаются. Стратегии запускаются
по одной; fallback не означает автоматическое применение всех экспериментов.

## Конфигурация и зависимости

Rust 2021 / minimum Rust 1.74: memory safety в parser/core, Result-based errors,
Cargo и встроенный test harness. Phase 1 использует только std, синхронные контракты,
без async runtime, CLI framework и сетевых библиотек. Cargo.lock появится при сборке.
TOML 1.0 выбран как понятный человеку формат; проверенный parser crate + serde
будут оценены при реализации loader вместо написания собственного TOML parser.

Полная схема в config/default.toml. При реализации: неизвестные ключи, неизвестная
или отключённая стратегия, payload_logging=true, wildcard IP и нулевые/избыточные
лимиты должны отклоняться. `use` проверяет схему и атомарно заменяет свой config.
Пути списков разрешаются относительно config, без traversal, внешних файлов и
reparse escape. Protected service config и runtime ACL определяются в Phase 8.
Изменение default.toml сейчас требует пересборки встроенного CLI-примера.

WinDivert 2.2 API — будущая documented dependency. Файлы DLL/SYS не входят в каркас.
Нужны официальное происхождение, подпись драйвера, проверенный hash и лицензионные
материалы до packaging. Приложение не скачивает зависимости при запуске. DLL будет
загружаться по защищённому абсолютному пути, без current-directory search.

Документация WinDivert подтверждает модель capture/reinject, shutdown/drain и
различие sniff/divert: https://reqrypt.org/windivert-doc.html
Лицензия сторонней зависимости: https://reqrypt.org/windivert.html
Изучалась API-документация; sample source и исходники zapret не использовались.

## Служба, диагностика и тестер

Phase 8: SCM API, ServiceName LocalDpiBypass, DisplayName Local DPI Bypass,
видимая auto-start служба устанавливается только явным service install.
Команды start/stop/restart управляют SCM; foreground dry-run — отдельный CLI путь.
Бинарник/config/logs размещаются в защищённых каталогах, quoted ImagePath;
SCM права и локальный IPC ACL запрещают команды от непривилегированных процессов.
Статистика содержит только counters и выбранный профиль. Никакого remote IPC.
Remove останавливает и удаляет именно эту службу, проверяя SCM pending deletion;
общий WinDivert driver нельзя удалять, если он используется другим приложением.

Phase 7: test запускает default/pass-through и каждую разрешённую стратегию
последовательно, свежими соединениями с timeout, без изменения постоянного профиля.
Если служба активна, тестер не создаёт конкурирующий handle: требует её остановки.
Проверяются сертификаты HTTPS, фиксированные цели и запрещены off-target redirects.
Каждая строка сообщает YouTube/Discord, elapsed ms, ошибки, число подтверждённых
strategy applications; без применения стратегия помечается INCONCLUSIVE.
QUIC/voice показываются отдельно. Нет гарантии воспроизводимости у каждого ISP.

Диагностика read-only: admin, WinDivert, DNS A/AAAA, HTTPS отдельно v4/v6,
SCM, доступные признаки proxy/VPN и фильтрующих драйверов. Проверки HTTP/3 и voice
могут возвращать Unsupported/NotRun, но не выдуманный OK. Никаких firewall изменений.

Логи будущей реализации: logs/app.log, bounded rotation, только lifecycle,
профиль, counters и фиксированные коды/результаты диагностики. Ни raw packet,
ни SNI, IP отдельных пользовательских потоков, URL, заголовки или TLS bytes.
Список настроенных destinations показывается config show, а dry-run — агрегатами
по preset/protocol/reason без packet dump.

````

## docs/roadmap.md

SHA-256: `a1dac03c919f193ad61943200ac8a9e1477bd82be69e76e5c95980111d569188`

````
# Этапы и критерии приёмки

Phase 1 — текущий каркас; переход к Phase 2 остановлен по заданию пользователя.
После каждого этапа: build, tests, полный список изменений, решения и ограничения.

| Phase | Работа | Обязательная проверка |
|---|---|---|
| 1 | Контракты, CLI skeleton, схема config, threat model | Cargo build/test, honest unavailable states, gate tests |
| 2 | WinDivert capture/inspect/reinject, sniff dry-run | Windows admin lab, byte-exact pass-through, shutdown/drain/send errors |
| 3 | TOML/TXT parser, allow/exclude, bounded flow state | Config unknown keys/paths, domain boundaries, IPv4/v6 CIDR, exclude priority |
| 4 | Первая TCP segmentation strategy | TCP seq/flags/options/retransmit, checksum vectors, server receives same bytes |
| 5 | TLS metadata и QUIC Initial support | Truncated TLS, IPv6 ext headers, QUIC varint/version corpus; HTTPS/QUIC отдельно |
| 6 | Discord HTTPS и voice/STUN профиль | STUN malformed/length tests, explicit ports/IPs, media unchanged |
| 7 | Последовательный strategy tester | Timeouts, certificate errors, attribution, profile restore, no competing handles |
| 8 | SCM install/start/stop/remove | Windows VM integration: quoted path, ACL, reboot, idempotence, pending delete |
| 9 | Read-only diagnostics и counters/logging | Proxy/VPN/filter cases, Unsupported states, sanitized bounded logs |
| 10 | Release packaging и security review | Windows 10/11 clean VM, dependency license/hash/signature, complete uninstall |

Phase 1 tests являются контрактными; они **не заменяют** packet-parser, checksum,
TOML parser или реальный service install/remove suite. Эти реализации ещё отсутствуют.
Дальнейшие unit tests: IPv4 lengths/fragments, IPv6 extension bounds, TCP data offset,
UDP length, malformed inputs на каждой границе, checksum odd lengths и pseudoheaders,
TLS nested length mismatch, QUIC varint truncation, STUN padding и типы.
Excluded traffic проверяется byte-for-byte на реальном pipeline перед release.

Reorder, TLS record rewriting, decoy и UDP desync — кандидаты с отдельными критериями;
не обещается, что каждый можно сделать безопасным и полезным для любого провайдера.
Неподтверждённая стратегия остаётся disabled/unsupported.

````

## docs/threat-model.md

SHA-256: `c45438abcbcc2bbcf778969797917be2b8c780d63f8f3cd4ccae300f5d478776`

````
# Модель угроз

## Активы и границы доверия

Активы: целостность сетевых соединений владельца, приватность запросов,
неизменность excluded traffic, целостность привилегированного процесса/config.
Недоверенные входы: каждый сетевой байт, DNS, TOML/TXT, содержимое каталогов
непривилегированного пользователя, метаданные native API и результаты probes.
WinDivert/kernel и Windows SCM — граница доверенного OS компонента;
компрометация kernel или администратора находится вне предоставляемой защиты.

Наблюдающий/фильтрующий ISP — сторона, против классификации которой испытывается
локальная обработка. Это не анонимизация: ISP продолжает видеть адреса, timing,
размеры и доступные метаданные. Программа не обещает обход любого DPI.

| Угроза | Мера проекта | Остаточный риск / приёмка |
|---|---|---|
| Malformed packets, integer overflow | Rust safe core, checked bounds, лимиты | Fuzz и corpus IPv4/v6/TCP/UDP/TLS/QUIC/STUN до activation |
| Memory/CPU exhaustion | Flow/time/byte budgets, bounded queue | Высокая нагрузка может вызвать packet loss; нагрузочный тест |
| Ошибочное изменение чужого CDN flow | SNI grant на flow, явные IP grants, exclude first | ECH часто означает pass-through, не universal support |
| Подмена конфигурации службы | Admin-only ACL, validated atomic writes | Администратор может изменить всё; local user ACL tests |
| DLL hijack/подмена драйвера | Protected absolute path, official signature/hash | WinDivert остаётся привилегированной dependency |
| Утечка payload через logs/errors | Fixed event fields; packet types без Debug | Review всех error paths и log privacy tests |
| Обрыв при split/reorder/decoy | Validated plans, disabled experiments, staged tests | Reinjection не transactional, частичная отправка возможна |
| Вызов управления удалённо | Нет listener, remote API, plugin DLL loader | Локальные SCM/IPC права проверяются в Phase 8 |
| DNS poisoning и ложный grant | DNS не даёт domain-wide IP authorization | Probe certificate verification обязательна |
| Конфликт других WFP/WinDivert приложений | Bounded startup, diagnosis, no competing tester | Полное обнаружение всех фильтров не гарантируется |

## Непересекаемые ограничения

Никаких browser password/cookie/token/Local Storage/profile DB reads.
Доступ к файлам только своего приложения и его явно заданной конфигурации.
Никакой телеметрии, аналитики, remote execution, скрытия процесса, obfuscation,
Scheduled Tasks, Run registry keys, Defender modifications/exclusions.
Нет updater, скачивания/запуска EXE/DLL, автоматической установки dependencies.
Firewall rules не изменяются. Установка службы возможна только по явной команде.
Эти требования относятся ко всем будущим фазам, а не только текущему каркасу.

## Сетевые соединения самого приложения

Phase 1: **ни одного**. Программа не использует sockets, DNS или HTTP client.

Будущий обычный capture: перехватывает локальный трафик; нового external route нет.
Test/diagnose: явные DNS запросы системному resolver и HTTPS GET только
https://www.youtube.com/ и https://discord.com/ с ограниченными timeout/body size,
без cookies, tokens, credentials и browser state. Ответы не сохраняются в logs.
Системный TLS/DNS stack может делать собственные certificate/resolver запросы;
это отдельно проверяется и документируется при выборе backend.
QUIC probe будет только к указанным целям UDP/443 после реализации отдельного
проверяемого клиента; voice probe endpoints сначала должны быть явно документированы.
Ни discovery, ни TLS сертификаты не разрешают произвольные новые probe endpoints.

## Security review gates

До Phase 2: capture filter scope, trusted driver loading, error/shutdown semantics.
До Phase 4: malformed/fuzz suite, exclude guarantees, packet sequence/checksums,
bounded memory, regression pcap fixtures без реальных пользовательских payload.
До Phase 8: SCM ACL, protected install path, local IPC authorization, remove tests.
До release: dependency hashes/licenses, SBOM, reproducible build instructions,
signature procedure, log privacy and no unauthorized persistence review.

````

## docs/verification.md

SHA-256: `ef65bb1c0842f441f3d39110f0cb3c03b059140561e1338f989ea2570da712ba`

````
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
````

## LICENSE

SHA-256: `d090c29dc447bd38701a78b9e88462f79ef0d3773f09550aa6326857ae0b6661`

````
MIT License

Copyright (c) 2026 Local DPI Bypass contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

````

## README.md

SHA-256: `1a84889f84649e4b869f639cab327c6b7c8d943fde8546e03f239d24cc3475af`

````
# Local DPI Bypass

Clean-room open-source каркас локального Windows 10/11 приложения на Rust.
Лицензия MIT. Выполнен **Phase 1**; обход DPI и перехват пакетов ещё не реализованы.
Исходники Flowseal/zapret, BAT-файлы и winws не использовались.

Топология будущей реализации: `client -> Discord/YouTube server`.
Внешнего VPN, proxy, туннеля, управляющего сервера и телеметрии нет.

## Сборка

Нужны Rust >= 1.74, Cargo и linker для выбранной платформы. На Windows:
Rust MSVC toolchain, Visual Studio Build Tools с C++ workload и Windows SDK.
Phase 1 не требует WinDivert, прав администратора или подключения к сети.

```powershell
cargo build --offline --all-targets
cargo test --offline
cargo run --offline -- status
cargo run --offline -- strategies
cargo run --offline -- config show
```

`status` показывает возможности каркаса, а не состояние установленной службы.
`config show` выводит встроенный пример, а не конфигурацию с диска.
Остальные запрошенные команды распознаны, но возвращают код 2 с объяснением.
В частности, `start --dry-run` ещё не наблюдает пакеты, `test` не проверяет сайты,
а `service install` ничего не устанавливает. Успех обозначается кодом 0.

## Структура

```text
src/
  lib.rs
  Core/          # PacketEngine, контекст, счётчики, схема Config
  PacketCapture/ # контракт адаптера драйвера
  Strategies/    # Strategy, pass-through, обязательный admission gate
  Filtering/     # решения фильтра, безопасный DenyAll
  Service/       # контракт SCM и явный unavailable-адаптер
  Diagnostics/   # контракт результатов проверок
  CLI/           # чистый диспетчер команд и main
config/
  default.toml
  domains.txt, ips.txt, exclude-domains.txt, exclude-ips.txt
  presets/{youtube,discord,discord-voice}/
tests/contracts.rs
docs/
  architecture.md
  threat-model.md
  roadmap.md
  verification.md
.github/workflows/ci.yml
```

Preset `custom` использует `config/domains.txt` и `config/ips.txt`.
Готового exe, DLL, драйвера, installer и updater в репозитории нет.

См. [архитектуру](docs/architecture.md), [модель угроз](docs/threat-model.md),
[этапы и критерии приёмки](docs/roadmap.md) и [проверки](docs/verification.md).
Полный снимок созданных исходных файлов предоставляется отдельно в PHASE1-FILES.md.

````

## src/CLI/main.rs

SHA-256: `9aad6c48b7bb382742ad4f77f1125ba4b7f70b52052660beab60452a21e9cbfe`

````
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let reply = local_dpi_bypass::cli::dispatch(&borrowed);
    if reply.code == 0 { println!("{}", reply.text); }
    else { eprintln!("{}", reply.text); }
    std::process::ExitCode::from(reply.code)
}

````

## src/CLI/mod.rs

SHA-256: `506bf41e7cd95c33c42e82d4cbbb1f0a2932eda51d6bd7661c14b87a11eeec0f`

````
pub const HELP: &str = "Local DPI Bypass — Phase 1 (no packet interception)
Implemented: status | strategies | config show | help
Reserved: start [--dry-run] | stop | restart | use <strategy>
          test | diagnose | service install|remove|status | logs
Reserved commands return exit code 2 without side effects.";

pub struct Reply { pub code: u8, pub text: String }

/// Pure dispatch: no filesystem, network, registry or SCM access.
pub fn dispatch(args: &[&str]) -> Reply {
    let (code, text) = match args {
        [] | ["help"] | ["--help"] | ["-h"] => (0, HELP.to_owned()),
        ["status"] => (0, "Phase: 1\nEngine: unavailable\nService: not queried\nStrategy: pass-through (built-in default)\nConfiguration: not loaded\nPacket counters: unavailable".into()),
        ["strategies"] => (0, "pass-through: available as pure strategy; engine unavailable\nsplit-tls: planned\nsplit-tcp: planned\nreorder / decoy / quic / stun: design candidates, disabled".into()),
        ["config", "show"] => (0, format!("# Built-in example, NOT loaded runtime configuration\n{}", crate::core::config::EXAMPLE_TOML)),
        ["start"] | ["start", "--dry-run"] | ["stop"] | ["restart"] |
        ["test"] | ["diagnose"] | ["logs"] | ["use", _] |
        ["service", "install"] | ["service", "remove"] | ["service", "status"] =>
            (2, "Not implemented in Phase 1. No system changes or network probes performed.".into()),
        _ => (2, format!("Unknown command or arguments.\n{HELP}")),
    };
    Reply { code, text }
}

````

## src/Core/config.rs

SHA-256: `85d26ac49de71ba6a98a7ab385f23b7683c081ce48aa8e79595087966b8cdab6`

````
/// Compile-time schema only. TOML loading/validation arrives with filtering.
pub const EXAMPLE_TOML: &str = include_str!("../../config/default.toml");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Targets {
    pub youtube: bool,
    pub discord: bool,
    pub discord_voice: bool,
    pub custom: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_flows: usize,
    pub flow_idle_seconds: u32,
    pub max_initial_bytes: usize,
    pub max_packets_per_flow: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub schema_version: u32,
    pub targets: Targets,
    pub strategy: String,
    pub dry_run: bool,
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            targets: Targets { youtube: true, discord: true, discord_voice: false, custom: false },
            strategy: "pass-through".into(),
            dry_run: true,
            limits: Limits {
                max_flows: 4096, flow_idle_seconds: 30,
                max_initial_bytes: 16384, max_packets_per_flow: 4,
            },
        }
    }
}

````

## src/Core/mod.rs

SHA-256: `08dacff0cc52c1e8b68e93f531efbb933e07e93e74a1e7caae76710b89211d7c`

````
use std::net::IpAddr;

use crate::filtering::FilterDecision;

pub mod config;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport { Tcp, Udp }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialMetadata {
    Unknown,
    TlsClientHello,
    QuicInitial { version: u32 },
    Stun,
}

/// Parsed, bounded view. Never derive Debug: metadata can include private hosts.
/// SNI is optional: encrypted ClientHello and fragmented records may hide it.
pub struct PacketContext<'a> {
    pub packet: &'a [u8],
    pub destination: IpAddr,
    pub destination_port: u16,
    pub transport: Transport,
    pub server_name: Option<&'a str>,
    pub initial: InitialMetadata,
    pub initial_payload: bool,
    pub filter: FilterDecision,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub processed: u64,
    pub eligible: u64,
    pub modified: u64,
    pub errors: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode { Active, DryRun }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineError { NotImplemented, Capture, Send, InvalidConfiguration }

/// Adapter owns capture lifetime and per-flow state; callers own shutdown.
/// Future run implementation must stop receiving and drain before closing.
pub trait PacketEngine {
    fn run(&mut self, mode: RunMode, stop: &std::sync::atomic::AtomicBool)
        -> Result<Counters, EngineError>;
    fn counters(&self) -> Counters;
}

/// Explicitly unavailable; it cannot accidentally open a capture handle.
#[derive(Default)]
pub struct UnavailableEngine;

impl PacketEngine for UnavailableEngine {
    fn run(&mut self, _: RunMode, _: &std::sync::atomic::AtomicBool)
        -> Result<Counters, EngineError>
    {
        Err(EngineError::NotImplemented)
    }

    fn counters(&self) -> Counters { Counters::default() }
}

````

## src/Diagnostics/mod.rs

SHA-256: `78ee7fb856aefd823351d0f5e3bb9b113ba2894bb37518b3ba4c22d006edc959`

````
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus { Ok, Failed, Unsupported, NotRun }

pub struct CheckResult {
    pub name: &'static str,
    pub status: CheckStatus,
    /// Human-readable, sanitized message; never include packet data.
    pub message: String,
}

pub trait Diagnostics {
    /// Network probes are allowed only after an explicit test/diagnose command.
    fn run(&self) -> Vec<CheckResult>;
}

pub const PLANNED_CHECKS: &[&str] = &[
    "Administrator privileges", "WinDivert availability",
    "DNS / IPv4 / IPv6", "YouTube HTTPS", "Discord HTTPS",
    "QUIC", "Discord voice prerequisites", "Proxy / VPN settings",
    "Packet-filter drivers", "Windows service",
];

````

## src/Filtering/mod.rs

SHA-256: `dce33258a0cdf117418f870af175e9a34d5309d3d1f0007c70e6128a91d3d376`

````
use crate::core::PacketContext;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterDecision { Allow, Exclude, NoMatch, Unknown }

/// Exclusion always wins. Unknown classification never authorizes a strategy.
pub trait DestinationFilter {
    fn evaluate(&self, context: &PacketContext<'_>) -> FilterDecision;
}

/// Phase 1 default until a validated allowlist engine exists.
pub struct DenyAll;

impl DestinationFilter for DenyAll {
    fn evaluate(&self, _: &PacketContext<'_>) -> FilterDecision {
        FilterDecision::NoMatch
    }
}

````

## src/lib.rs

SHA-256: `b3fa68c0e91bbb69bfb542ab41c0164e52abfbfcfcf662ee2f76106afc2e03be`

````
//! Phase 1 contracts. No driver, sockets, service mutations or packet parsing.
#![forbid(unsafe_code)]

#[path = "Core/mod.rs"]
pub mod core;
#[path = "PacketCapture/mod.rs"]
pub mod capture;
#[path = "Strategies/mod.rs"]
pub mod strategies;
#[path = "Filtering/mod.rs"]
pub mod filtering;
#[path = "Service/mod.rs"]
pub mod service;
#[path = "Diagnostics/mod.rs"]
pub mod diagnostics;
#[path = "CLI/mod.rs"]
pub mod cli;

````

## src/PacketCapture/mod.rs

SHA-256: `17493661da25a7b91b99d31a064d3e476eb63d87fdfbc08fae6338718851e3aa`

````
/// A backend retains its native address, interface, direction and checksum flags.
/// Neither packet bytes nor backend metadata may be written to logs.
pub struct CapturedPacket<A> {
    pub bytes: Vec<u8>,
    pub address: A,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureError { Unavailable, Receive, Send, Shutdown }

/// WinDivert implementation is deliberately absent in Phase 1.
/// None means stopped and drained, never a transient receive error.
pub trait PacketCapture {
    type Address;
    fn receive(&mut self) -> Result<Option<CapturedPacket<Self::Address>>, CaptureError>;
    fn send(&mut self, packet: &CapturedPacket<Self::Address>) -> Result<(), CaptureError>;
    fn recalculate_checksums(&self, packet: &mut CapturedPacket<Self::Address>)
        -> Result<(), CaptureError>;
    fn shutdown_receive(&mut self) -> Result<(), CaptureError>;
}

````

## src/Service/mod.rs

SHA-256: `e299ec97658ff93b2b820fa4a10033a8ff578af6b9f72b3faa976014d7e094e8`

````
pub const SERVICE_NAME: &str = "LocalDpiBypass";
pub const DISPLAY_NAME: &str = "Local DPI Bypass";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState { NotInstalled, Stopped, Running, Unknown }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError { NotImplemented, AccessDenied, OperatingSystem }

/// Future SCM adapter: no shell commands, scheduled tasks or Run keys.
pub trait ServiceManager {
    fn status(&self) -> Result<ServiceState, ServiceError>;
    fn install(&self) -> Result<(), ServiceError>;
    fn remove(&self) -> Result<(), ServiceError>;
    fn start(&self) -> Result<(), ServiceError>;
    fn stop(&self) -> Result<(), ServiceError>;
}

pub struct UnavailableService;

impl ServiceManager for UnavailableService {
    fn status(&self) -> Result<ServiceState, ServiceError> { Err(ServiceError::NotImplemented) }
    fn install(&self) -> Result<(), ServiceError> { Err(ServiceError::NotImplemented) }
    fn remove(&self) -> Result<(), ServiceError> { Err(ServiceError::NotImplemented) }
    fn start(&self) -> Result<(), ServiceError> { Err(ServiceError::NotImplemented) }
    fn stop(&self) -> Result<(), ServiceError> { Err(ServiceError::NotImplemented) }
}

````

## src/Strategies/mod.rs

SHA-256: `efeda2266bd294e7b00b749a6bff7a38d9daf8157eafc38de663bc0ea46a191b`

````
use crate::core::{PacketContext, RunMode};
use crate::filtering::FilterDecision;

/// Plans are validated by the engine; strategies never send packets themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessResult {
    PassThrough,
    /// TCP payload offset, not an IP packet or TLS-record offset.
    SplitTcp { payload_offset: usize },
    WouldModify,
}

pub trait Strategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn matches(&self, context: &PacketContext<'_>) -> bool;
    fn process(&self, context: &PacketContext<'_>) -> ProcessResult;
}

pub struct PassThrough;

impl Strategy for PassThrough {
    fn name(&self) -> &'static str { "pass-through" }
    fn matches(&self, _: &PacketContext<'_>) -> bool { true }
    fn process(&self, _: &PacketContext<'_>) -> ProcessResult { ProcessResult::PassThrough }
}

/// Gate shared by the future engine. This alone does not validate packet syntax.
/// Only the engine may attach a trusted filter decision after parsing/filtering.
pub fn evaluate(strategy: &dyn Strategy, context: &PacketContext<'_>, mode: RunMode)
    -> ProcessResult
{
    if context.filter != FilterDecision::Allow || !context.initial_payload {
        return ProcessResult::PassThrough;
    }
    if !strategy.matches(context) { return ProcessResult::PassThrough; }
    let result = strategy.process(context);
    if mode == RunMode::DryRun && result != ProcessResult::PassThrough {
        ProcessResult::WouldModify
    } else {
        result
    }
}

````

## tests/contracts.rs

SHA-256: `7c154be5e79428facabc41f33085195f983615388529defce735e0ae1f4c0363`

````
use std::sync::atomic::AtomicBool;
use local_dpi_bypass::{cli, core::*, filtering::*, service::*, strategies::*};

fn context(filter: FilterDecision) -> PacketContext<'static> {
    PacketContext {
        packet: &[], destination: "192.0.2.1".parse().unwrap(),
        destination_port: 443, transport: Transport::Tcp,
        server_name: Some("example.invalid"), initial: InitialMetadata::Unknown,
        initial_payload: true, filter,
    }
}

struct MustNotRun;
impl Strategy for MustNotRun {
    fn name(&self) -> &'static str { "test" }
    fn matches(&self, _: &PacketContext<'_>) -> bool { panic!("unauthorized matching") }
    fn process(&self, _: &PacketContext<'_>) -> ProcessResult { panic!("unauthorized strategy") }
}

#[test]
fn excluded_unknown_and_unmatched_never_reach_strategy() {
    for decision in [FilterDecision::Exclude, FilterDecision::Unknown, FilterDecision::NoMatch] {
        for mode in [RunMode::Active, RunMode::DryRun] {
            assert_eq!(evaluate(&MustNotRun, &context(decision), mode), ProcessResult::PassThrough);
        }
    }
}

#[test]
fn later_payload_never_reaches_strategy() {
    let mut ctx = context(FilterDecision::Allow);
    ctx.initial_payload = false;
    assert_eq!(evaluate(&MustNotRun, &ctx, RunMode::Active), ProcessResult::PassThrough);
}

struct PlannedSplit;
impl Strategy for PlannedSplit {
    fn name(&self) -> &'static str { "test-split" }
    fn matches(&self, _: &PacketContext<'_>) -> bool { true }
    fn process(&self, _: &PacketContext<'_>) -> ProcessResult {
        ProcessResult::SplitTcp { payload_offset: 1 }
    }
}

#[test]
fn dry_run_suppresses_modification_plan() {
    let ctx = context(FilterDecision::Allow);
    assert_eq!(evaluate(&PlannedSplit, &ctx, RunMode::DryRun), ProcessResult::WouldModify);
    assert_eq!(evaluate(&PlannedSplit, &ctx, RunMode::Active), ProcessResult::SplitTcp { payload_offset: 1 });
    assert_eq!(evaluate(&PassThrough, &ctx, RunMode::DryRun), ProcessResult::PassThrough);
}

#[test]
fn unavailable_engine_does_not_claim_success() {
    let mut engine = UnavailableEngine;
    for mode in [RunMode::Active, RunMode::DryRun] {
        assert_eq!(engine.run(mode, &AtomicBool::new(false)), Err(EngineError::NotImplemented));
    }
    assert_eq!(engine.counters(), Counters::default());
}

#[test]
fn install_remove_and_service_operations_are_unavailable() {
    let manager = UnavailableService;
    assert_eq!(manager.install(), Err(ServiceError::NotImplemented));
    assert_eq!(manager.remove(), Err(ServiceError::NotImplemented));
    assert_eq!(manager.start(), Err(ServiceError::NotImplemented));
    assert_eq!(manager.stop(), Err(ServiceError::NotImplemented));
    assert_eq!(manager.status(), Err(ServiceError::NotImplemented));
}

#[test]
fn phase_one_cli_is_honest_about_reserved_operations() {
    for args in [vec!["start"], vec!["start", "--dry-run"], vec!["stop"],
        vec!["restart"], vec!["use", "split-tls"], vec!["test"], vec!["diagnose"],
        vec!["logs"], vec!["service", "install"], vec!["service", "remove"],
        vec!["service", "status"]] {
        assert_eq!(cli::dispatch(&args).code, 2);
    }
    assert_eq!(cli::dispatch(&["start", "--unknown"]).code, 2);
    assert!(cli::dispatch(&["status"]).text.contains("not queried"));
}

#[test]
fn safe_defaults_and_deny_all_filter() {
    let config = core_config();
    assert!(config.dry_run);
    assert!(!config.targets.discord_voice);
    assert!(!config.targets.custom);
    assert_eq!(config.strategy, "pass-through");
    assert_eq!(DenyAll.evaluate(&context(FilterDecision::Allow)), FilterDecision::NoMatch);
}

fn core_config() -> config::Config { config::Config::default() }

````
