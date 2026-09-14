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

