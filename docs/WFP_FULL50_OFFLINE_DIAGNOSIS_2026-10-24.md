# WFP/Core: offline-разбор full50, 24 октября 2026

## Область и результат

Разобраны сохранённые данные preview41/source `7e40248`, attempt
`20261024-124933-0f41ea6ddd64496f8206634cbdaf39e1`: 36 PASS / 14 FAIL.
Новых product/driver/WinDbg trials, сборок, установки или системных изменений
не выполнялось. Новые продуктовые тесты и изменения лаборатории не добавлены.
Offline review читает JSON, capture и исходники; это не runtime-проверка продукта.

P1/P2/P4 объясняются недостаточным UDP-контрактом baseline driver/Core.
Для P3 найдено существенное альтернативное объяснение: перенаправление
служебного TCP socketpair при создании asyncio loop **до SSH connect**.
Все восемь records выбирают DIRECT, но baseline всё равно использует proxy:
это уже исправленный в340bdc8 дефект переноса RuleAction внутри Core.
Называть ephemeral destinations доказанным повреждением SSH destination нельзя.
Точная принадлежность восьми исторических endpoints без стеков не установлена.

## Ревизии и источники

- Проверенный full50 bundle: Core/CLI source
  `b3596272a8dc8898790b016d1e4c488c2fdc917d`, сохранённый baseline SYS SHA256
  `3e5c3c709ee8c8800628f04b5550f3a82377deb264b045ab2f2ccbab3fd8fb4c`.
  Это не новая kernel build из b359627. Bundle:
  `C:/src/ProxyBridge-TestLab/artifacts/product-builds/driver-b359627-wfp-comparison-20261024-r1`.
- Raw evidence: `%LOCALAPPDATA%/ProxyBridge-TestLab/traffic-lab/20261024-124933-0f41ea6ddd64496f8206634cbdaf39e1`.
- Актуальные исходные отчёты, docs commit `b0886d9737e532a3ffd47873b0a0dfabe3a0e453`:
  `C:/Users/LabAdmin/.codex/worktrees/testlab-development/ProxyBridge-TestLab/docs/`
  `PRODUCT_FAILURES_DEFERRED_2026-10-24.md`,
  `PREVIEW41_FULL50_VALIDATION_2026-10-24.md`, `WFP_FULL50_ANALYSIS_2026-10-24.md`.
- Производный capture: тот же development worktree,
  `artifacts/preview41-full50-review/product-log.txt`.
- Новый private offline review:
  `C:/src/ProxyBridge-TestLab/artifacts/diagnostics/full50-product-offline-20261024-r1/review.py`
  и `review.json`. Exit0; проверены два worker, восемь redirect events,
  восемь reply2; сохранены SHA256 18 входов, включая raw reports/console,
  bundle, runtime stdlib и совпадающие frozen/current SSH/worker/dependencies.
  Raw evidence не изменялись. Эти private файлы не включать в Git.

При входе `C:/src/ProxyBridge-Driver` был чистым на
`137d1286f55311f39fda06cf717c993bdd5747a4`, `codeql-whcp-fixes-ea115fa`.
Создана только документальная ветка `codex/wfp-full50-offline-diagnosis`
непосредственно от `driver` b359627. Исходная ветка сохранена.
Remote SHA `driver`, UDP и TCP-веток сверены через ls-remote; исходник
`ProxyBridgeDrv_user.c` b359627 дополнительно прочитан через GitHub connector.
Serena среди доступных инструментов нет. Desktop/Context7 для чтения
локальных C/Python исходников не требовались.

## Наблюдения и локализация UDP

| ID | Наблюдение full50 | Механизм baseline и граница вывода |
|---|---|---|
| P1 | Пять connected/wildcard UDP-сценариев не доставляют payload до origin | `ProxyBridgeDrv.c:191` регистрирует local tuple до redirect; `pbdrv_state.c:95,122` требует точное совпадение адреса. Wildcard/concrete mismatch подтверждён прежним driver-only опытом на том же SYS. Кроме того, `:97` заменяет назначение при том же source tuple; прежний опыт с двумя назначениями подтвердил потерю A. Full50 не повторял IOCTL trial. |
| P2 | 11298 полученных datagrams; 8226 valid-HMAC replies с чужим flow_id; 3072 own-flow, все с неверного source | `pb_relay_udp.c:313` выбирает most-recent client по remote tuple. Общая SOCKS association принадлежит proxy config, не endpoint приложения. Ответ произвольного протокола нельзя надёжно соотнести с одним из нескольких клиентов такой эвристикой. Это cross-delivery, а не физическая потеря 8226 пакетов. |
| P4 | Все 20 QUIC/HTTP3 flows и полученный DNS reply имеют source `127.0.0.1:34011` | `pb_relay_udp.c:344` отправляет IPv4 payload через обычный `sendto(udp_relay_socket, ...)`, связанный с портом34011. Baseline kernel не содержит обратного UDP packet-injection пути. Наблюдаемый source соответствует этому коду. Сам факт WFP connect redirect не заменяет реализацию прозрачного возврата. |

Счётчики source и identity перекрываются; их нельзя складывать как потери.
UDP packet channel и изолированные association в уже существующей UDP-ветке
устраняют эти архитектурные причины в проверенных локальных условиях;
простой wildcard fallback или смена last_activity на FIFO недостаточны.

Microsoft отдельно описывает сбой connected UDP при локальном ALE redirect:
[KB](https://learn.microsoft.com/en-us/troubleshoot/windows-hardware/drivers/redirection-connected-udp-traffic-local-proxy-fail).
Это дополнительный контекст, не доказательство того, какой именно механизм
сработал в каждом из пяти full50 случаев. Не менять worker connect на sendto
ради сокрытия отказа. Документированный порядок UDP WFP layers:
[UDP Packet Flows](https://learn.microsoft.com/en-us/windows/win32/fwp/udp-packet-flows).

## P3: служебный loopback вместо доказанного повреждения destination

Подтверждённые сохранённые факты:

| Worker | Ожидаемый application port | Core accepted destinations | Результат |
|---|---|---|---|
| SSH PID6204 | 42516 | 56118, 56120, 56119, 56121 | 4 flows, worker deadline45s, результатов flows нет |
| SFTP PID11532 | 42517 | 62475, 62474, 62477, 62476 | 4 flows, worker deadline45s, результатов flows нет |

Capture lines3224–3233 и3254–3263: ровно восемь SOCKS CONNECT reply2.
Для этих PID нет accepted redirect с destination42516/42517.
**Все восемь records содержат `action=1 cfg=0`.** В точном
`Windows/src/core/ProxyBridge.h` b359627: PROXY=0, DIRECT=1, BLOCK=2.
Следовательно, policy уже выбрала DIRECT для этих endpoints. Это не записи
PROXY-решения для исходных SSH/SFTP портов.

Frozen preview41 `src/trafficlab/ssh_client.py` совпадает с development copy,
SHA256 `70c69a7a5d0a357fe4910f318628eb8f0c3eb17155a6f8303fab116a9809ac53`.
Последовательность в фактически поставленном коде:

1. `ssh_flow` создаёт coroutine `execute()`, затем вызывает `asyncio.run(execute())`
   (`ssh_client.py:113`). Тело coroutine, включая socket connect на application
   port (`:36`), ещё не исполнялось.
2. `asyncio/runners.py:137` создаёт loop; default Windows policy — Proactor
   (`asyncio/windows_events.py:952`). В исходниках trafficlab нет смены policy.
3. `asyncio/proactor_events.py:639,784` создаёт self pipe через socket.socketpair.
4. В runtime Python3.11.9 нет native `_socket.socketpair`: это установлено
   introspection-only командой `python.exe -I -S -c ...`, без создания sockets,
   запуска asyncio loop или загрузки продукта. Используется `socket.py:616`.
5. Эта реализация bind-ит loopback listener на порт0, подключает второй socket
   к полученному ephemeral port и синхронно ждёт `lsock.accept()` (`:645`).
6. Baseline driver при включённом redirectLoopbackApps перехватывает соединения
   watched worker, включая такие служебные TCP connects. Rule matching выбирает
   DIRECT, однако `prepare_tcp_connection` не сохраняет act в CONNECTION_CONFIG.
   `connection_handler` b359627 (`pb_relay_tcp.c:303`) всегда запрашивает proxy;
   cfg0 означает первый доступный (`pb_proxy.c:5–16`). Core отправляет их
   в SOCKS, где строгая allowlist закономерно отвечает2. Исходный listener
   не получает connect, поэтому создание loop может застрять до worker deadline.

**Доказанный дефект маршрутизации:** DIRECT превращается в PROXY; это видно
одновременно по action enum, восьми capture records и handler baseline.
Существующий `340bdc8` сохраняет action и выполняет отдельный DIRECT connect
без proxy fallback. Общий дефект DIRECT уже проверен прежними runtime gates.

**Гипотеза с сильной поддержкой:** именно эти socketpair connects составляют
восемь capture records. Число, тип портов и остановка до application destination
согласуются с ней. Наличие ожидаемого PID в record подтверждает приложение,
но не назначение конкретного вызова connect внутри этого приложения.
Данные не содержат stack/listener-owner snapshot; поэтому индивидуальная
принадлежность всех восьми портов и блокировка accept не объявляются
измеренными фактами. Нет основания на этих данных чинить byte order, ABI
или WFP original-destination context. User-mode getter просто возвращает
контекст через WSAIoctl; сам порт он не переставляет.

Первый проверяемый кандидат — существующий TCP DIRECT fix340bdc8, без нового
патча driver/ABI. Восстановление именно SSH/SFTP после него не измерено.
Не расширять SOCKS allowlist до ephemeral ports, не выключать глобально
localhost proxy и не заменять asyncio loop в стенде ради PASS. Новые исключения
loopback IPC не нужны для исправления уже выбранного DIRECT; их проектирование
до проверки имеющегося исправления было бы преждевременным расширением scope.

## Уже выполненные исправления: не повторять старую работу

Remote состояния на проверке: `driver` b359627; `codex/udp-map-source-key`
`b9939135ba80c71ee9122727be84db0c56d7bc0b`; `codex/tcp-direct-route`
`340bdc839bed3c02d75dceb996cee68f39ecf045`.

- `C:/src/ProxyBridge-TestLab/docs/UDP_TESTLAB_BEFORE_AFTER_RESULTS_2026-10-22.md`
  уже фиксирует15072/15072 PROXY и столько же OFF ответов; final package1.1.0.0
  SYS `c1ab41935cc96afea18cdd6aec7916038d1683d1e45fce6dfefe8b1902607a6b`,
  Core `7a02e79b4cbb5bae55c3323fe1984c8468622d0f6bbfdcdf766dac992c070104`.
  Это локальные correctness gates и отдельная native matrix, не preview41 full50.
  Старый отрицательный trial30b4ec7 — промежуточный исторический результат.
- `TCP_DIRECT_FIX_VALIDATION_2026-10-23.md` и
  `TCP_DIRECT_BENCHMARK_RESULTS_2026-10-23.md` в той же docs directory уже
  описывают проверку340bdc8: отдельный Core action-routing fix и48 benchmark
  runs. Fix устраняет установленный дефект DIRECT, обнаруженный также в P3
  records; SSH/SFTP отдельно не перепроверялись. Это не UDP-ветка. Сообщение передачи
  «tcp-direct-route пока не проверялся» устарело относительно этих документов.
- Объединённого нового Core+SYS и его preview41 full50 в этих свидетельствах
  нет. Никакая ветка не переносилась в driver; PR/merge не создавались.

## Следующий ограниченный опыт — требует отдельного допуска

Цель: различить перехват asyncio self-pipe и повреждение SSH destination,
проверить существующий Core DIRECT fix,
не переустанавливая драйвер и не повторяя full50. Предлагаемый объём:

1. Прочитать свежие controller active/busy, driver/PnP и debugger state.
   При busy или активном debugger workload — остановиться без вмешательства.
   Использовать baseline SYS и два уже собранных Core с проверкой hashes; не менять trust,
   BCD, system proxy, power, package или KD. Physical PB-SUT не трогать.
2. Один private diagnostic child на agent VM: Python3.11.9 preview41,
   один asyncio loop, без SSH/TLS payload. Записать PID, собственный listener
   tuple и call-site/stack перед connect/accept; не патчить release файлы.
   Один OFF control, один baseline case и один340bdc8 case, не более8s каждый.
   Готовый private worker/timeout supervisor:
   `artifacts/diagnostics/full50-product-offline-20261024-r1/socketpair_probe.py`.
   Его AST проверен без выполнения; он не загружает Core и не управляет PnP.
   Explicit `--run --label off|baseline|tcp-direct --output <fresh-directory>`
   запускает только дочерний socketpair probe, stack dump через2s и kill по8s.
   Product controller выполняется отдельно, с собственным finally/cleanup.
3. WFP cases: отдельный контролируемый SOCKS endpoint со строгим отказом
   незаявленных destinations; одна process-specific TCP PROXY rule на42516,
   чтобы включить watchlist, но сохранить DIRECT fallback ephemeral-портов;
   loopback mode как в full50. Нельзя применять PROXY на все порты — такой
   опыт проверял бы другую policy. Сопоставить logged listener port с Core original destination
   и SOCKS CONNECT. Parent читает thread stacks до deadline, завершает только
   своего зависшего child, выполняет Core Stop и закрывает helpers.
4. Критерий гипотезы: OFF проходит; при baseline собственный listener port точно
   равен redirect destination с action=DIRECT, connect ошибочно виден в SOCKS,
   стек остаётся на socketpair accept до application callback. С340bdc8 callback
   завершается, этих connects в SOCKS нет. Это gate служебного IPC, а не полный
   SSH handshake или full50. Несовпадение опровергает
   атрибуцию; тогда нужен capture исходного application connect, а не правка
   allowlist. Не запускать длительные нагрузки после первого отказа.
5. Parent finally восстанавливает исходные driver/PnP state и проверяет
   отсутствие своих helpers/listeners. Если восстановление не подтверждено,
   явно сообщить фактическое состояние; не объявлять cleanup успешным.

Этот опыт пока **не запускался**. Подготовлен worker/timeout supervisor;
Core lifecycle и восстановление должны использовать контроллер после проверки
свежего состояния. Новая установка не нужна: оба Core используют baseline SYS.
Разрешение требуется по `C:/src/ProxyBridge-TestLab/AGENTS.md`, Scope and context:
“neither historical NEXT entries nor development permissions authorize diagnostic runs”.
Передача также прямо запрещает расширять прошлое разрешение WFP installation
на свежие trials. Допуск нужен к этому диагностическому запуску; установка
нового пакета в предложенный опыт не входит.

## Ограничения и продолжение

Flow-rate967/967 preview41 не доказывает исправление прежнего1/747 отказа;
он остаётся неатрибутированным.17 sub-stages не стартовали. Full50 ограничен
локальным IPv4 loopback, без24h soak и аттестации внешнего трафика.
Performance новой архитектуры данным разбором не измерялась.
Актуальная краткая точка продолжения: [checkpoint](PRODUCT_CHECKPOINT.md).
