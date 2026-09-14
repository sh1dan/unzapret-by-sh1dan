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

