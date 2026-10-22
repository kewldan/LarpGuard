# bot-shield

Self-hosted шлюз фильтрации ботов перед Traefik. Основной метод — отпечатки
клиента (TCP, TLS, HTTP/2, JS) и их согласованность с тем, кем клиент себя
заявляет. Архитектура, ADR и этапы: `docs/architecture.md` — читать перед
крупными изменениями, решения там приняты и обоснованы.

Этапы M0–M6 готовы (раздел 14 `docs/architecture.md`): TLS-фронт с
маршрутизацией по ClientHello, пассивные отпечатки и события в NATS →
ClickHouse, HTTP-прокси с вердиктами и правилами, rate limiting, docker-лейблы
и admin API, JS-челлендж и проверка краулеров, fail-open, поведение и
honeypot, tarpit/decoy, модель-сигнал, gRPC, HTTP/3, горячая перезагрузка.
Roadmap (раздел 14, «Статус: roadmap»): пробы челленджа, капча, IP-диапазоны
краулеров, Web Bot Auth, база ASN, XDP. Веб-консоль (`ui/`, ADR-017) —
отдельное приложение с BFF поверх admin API и ClickHouse.

## Команды

```bash
cmake -S . -B build -G Ninja          # первый configure качает зависимости
cmake --build build
ctest --test-dir build --output-on-failure
python3 -I tests/e2e/run_e2e.py build/src/bot-shield   # нужны curl с HTTP/2 и node
cmake --build build --target format        # clang-format на месте
cmake --build build --target format-check
cmake --build build --target tidy          # clang-tidy, должно быть 0 предупреждений
```

Консоль (`ui/`, Node.js 24):

```bash
npm --prefix ui ci
npm --prefix ui run dev:api                # BFF на моках (users.ts) :9901
npm --prefix ui run dev:web                # Vite :5173, /api → :9901
npm --prefix ui run lint && npm --prefix ui run typecheck   # lint = biome check
npm --prefix ui run format                 # biome check --write
npm --prefix ui test                       # vitest: web (jsdom) и node
npm --prefix ui run build && (cd ui && npx playwright test)
npm --prefix ui run e2e:docker             # со скриншотами, как в CI (-- --update-snapshots)
npm --prefix ui run tokens                 # tokens.css из tokens.ts
```

Санитайзеры: отдельный каталог `build-asan` с
`-DBOT_SHIELD_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug`, на macOS запускать с
`ASAN_OPTIONS=detect_leaks=0`.

Linux-проверка (`SO_REUSEPORT` с несколькими воркерами, `TCP_SAVED_SYN`
работают только там) — в контейнере `debian:trixie` с `build-essential cmake
ninja-build git python3 openssl curl nodejs clang` (`--privileged`, чтобы
шли XDP-тесты), исходники монтировать read-only.

CI — `.github/workflows/ci.yml`: format (clang-format 23.1.3 из PyPI),
clang-tidy (23.1.3, `debian:trixie`), тесты и e2e обычные и под ASan/UBSan,
джоб Console (Biome, tsc, vitest, сборка, Playwright со
скриншотами в образе `mcr.microsoft.com/playwright`); на `main` и тегах
`v*` после них — мультиархитектурные образы `ghcr.io/kewldan/larpguard` и
`ghcr.io/kewldan/larpguard-console` (`latest`, `sha-…`, semver). Версию
clang-format/clang-tidy менять в CI вместе с локальной.

## Готово, когда

- собирается без предупреждений в наших файлах;
- `ctest` и e2e проходят;
- `format-check` чистый и `tidy` даёт 0 предупреждений;
- изменения в сетевом коде, корутинах или парсерах дополнительно прогнаны под
  ASan/UBSan; платформенный код — под Linux.

## Код

- C++20, Google C++ Style: `.clang-format` (`BasedOnStyle: Google`) и
  `.clang-tidy` с проверкой именования. Поля классов `snake_case_`, у структур
  без подчёркивания; аксессоры `name()` / `set_name()`; константы `kName`.
- Include what you use: `misc-include-cleaner` и `.clangd` требуют прямых
  include для std и своих заголовков (сторонние библиотеки исключены).
  Заголовки, нужные только под `#if __linux__`, помечать
  `// IWYU pragma: keep`, иначе автоисправление на macOS их удалит.
- `NOLINT` — только адресно (`NOLINTNEXTLINE(check)`) и с причиной в
  комментарии строкой выше.
- Комментарии и сообщения в коде — на английском. `README.md` — на
  английском (с эмодзи, как сейчас); `docs/` — на русском.
- Зависимости фиксированы в `cmake/dependencies.cmake` (FetchContent,
  точные версии). Новые — так же, без системных пакетов.

## Устройство

- `src/tls/` — разбор ClientHello, хранилище сертификатов, опрос `acme.json`.
- `src/net/` — классификатор маршрута, PROXY v2, `PrefixedStream`,
  `Watchdog`, сокетные опции, `http_client` (блокирующий HTTPS-клиент для
  фоновых потоков — никогда на цикле воркера), `asn` (база iptoasn).
- `src/common/refresher` — `DataRefresher`: фоновые загрузки (диапазоны
  краулеров, ASN) с кешем в `data_dir`; новый скачиваемый набор — новый
  `RefreshSource` в `main.cc`. `compress` — zlib (gunzip, PNG).
- `src/server/` — обработчики соединений, воркеры, `/metrics` и `/health`
  (503, если `Heartbeats` воркера устарел).
  `ConnectionObserver` в `connection.cc` собирает отпечатки и шлёт события.
  `whoami` — отчёт `/__bs/whoami` (вердикт вместо действия, `whoami: true`).
- `src/fp/` — отпечатки и пассивные HTTP-разборщики. `src/fp/foxio/` —
  JA4T/JA4H под FoxIO License, только за `BOT_SHIELD_FOXIO`; код вне этой
  папки не должен от них зависеть (только `#if BOT_SHIELD_FOXIO`).
- `src/proxy/` — HTTP-прокси: `h1_server`, `h2_server` (к клиенту),
  `h2_upstream` + `upstream_pool` (к Traefik), `exchange` связывает стороны.
  Вердикты по запросу — в `ConnectionObserver::OnProxyRequest`
  (`exchange.RespondLocally()` или правка `exchange.request.headers`).
- `src/quic/` — HTTP/3: `QuicServer` на воркер (UDP, ngtcp2 + nghttp3),
  запросы — те же `Exchange` в HTTP/2-пул, вердикты через
  `MakeQuicObserver`. Колбэки ngtcp2/nghttp3 нельзя вызывать повторно
  изнутри них же; запись пакетов только через `Flush()`, который внутри
  вызовов ngtcp2/nghttp3 (`CallbackScope`) откладывается через `post`.
  Буфер пакета — поле соединения: после `NGTCP2_ERR_WRITE_MORE` ngtcp2
  дописывает пакет в него же в следующем вызове. HTTP/3 поднимается при
  первых данных потока, не только после рукопожатия (1-RTT-запрос может
  прийти раньше `Finished`). Удаление соединения отложено (`Remove` через
  `post`, по `weak_ptr`, не по адресу): оно может быть внутри своего
  колбэка.
- `src/score/` — скоринг (`Scorer`), правила (`rules.cc`: лексер, парсер,
  проверка типов, вычисление; новое поле — в `kFields` и `FieldValue`) и
  политика (`Policy`: shadow/enforce, `policy.hosts`). Сигналы и веса — в `deploy/fingerprints.yaml`; копия
  встроена в `src/fp/library.cc` и должна совпадать с файлом (тест
  `LibraryTest.BuiltInMatchesDeployFile`). Значения отпечатков в библиотеку —
  только проверяемые (пересчитанные или из спецификаций), не по памяти.
- `src/ratelimit/` — GCRA (`gcra`), общее для всех воркеров шардированное
  хранилище (`store`: состояние не делить по воркерам — лимит умножится),
  описание лимитов и ключей (`limits`). Лимиты проверяются после вердикта
  в `ConnectionObserver::CheckRateLimits`, лимиты соединений — в `accept`.
- `src/docker/` — клиент Docker API по unix-сокету (`client`), разбор
  лейблов `botshield.*` в снапшот `LabelPolicies` (`labels`), опрос
  (`watcher`). Приоритет режима: `policy.hosts` в YAML → лейблы → `mode`.
- `src/admin/` — admin API на unix-сокете (`server`, свой поток
  `AdminServer`, не воркер), оперативные списки (`lists`: главнее правил,
  allow побеждает block), журнал решений (`decision_log`; в ответе ещё
  `ip_prefix`/`ip_hash` как в событиях), режимы хостов из консоли
  (`modes`: главнее `policy.hosts` и лейблов, `admin.modes_file`,
  применяются пересборкой `VerdictSet` через `WithConsoleModes`), режим
  «под атакой» (`attack`). Новый эндпоинт — в `HandleAdminRequest` + тест в
  `admin_test.cc`; если он нужен консоли — метод в
  `ui/server/gateway/admin.ts` со схемой ответа.
- `src/watchdog/` — `bot-shield-watchdog` (fail-open, ADR-012): опрос
  `/health` и команды nftables из `deploy/failopen/`. `src/common/systemd` —
  `sd_notify` без libsystemd.
- `src/behavior/` — `BehaviorStore`: поведение клиентов в окне и метки
  honeypot, общее для воркеров (шардированное, ограниченное). Новый сигнал —
  в `OnRequest` + вес в `deploy/fingerprints.yaml` и `src/fp/library.cc`.
- `src/model/` — признаки (`features.h`, набор `kFeatureSetVersion`) и
  `GbdtModel`. Новый или изменённый признак — новая версия набора, правка
  `FEATURE_NAMES` в `tools/train_model.py` и пересоздание
  `tests/data/gbdt_fixture.json` (`train_model.py --fixture`).
- `src/challenge/` — JS-челлендж (`challenger`: `CheckSignals` с тремя
  уровнями находок), JS страниц (`scripts.cc`; новый сигнал — сбор в
  `ProbesJs`, проверка в `CheckSignals`, тест в `captcha_test.cc`, заглушка
  в node-harness e2e), капча (`captcha`: свой пазл `puzzle` и провайдеры с
  фоновым siteverify), токены (`token`: `v1` — JS, `v2` с уровнем — капча).
  Ответ после фоновой проверки — `Exchange::DeferLocalResponse()` и
  `RespondLocally()` через `asio::post` на executor соединения.
- `src/crawler/` — каталог (`crawlers`, у краулера `domains` и `ranges`),
  rDNS (`verifier`), IP-диапазоны (`ranges`), Web Bot Auth (`web_bot_auth`,
  проверяется на тест-векторах драфта).
- `src/xdp/` — XDP-фильтр: `filter.bpf.c` (без системных заголовков, раскладка
  карт и `struct config` продублирована в `xdp_filter.cc`), вшивается
  `tools/bpf_embed.py`, загрузчик без libbpf. Собирается только на Linux с
  clang; тесты — через `BPF_PROG_TEST_RUN` (нужны права, иначе skip).
- `src/server/verdicts` — `VerdictSet`: всё, что решает вердикт и
  перезагружается без рестарта (библиотека, политика, правила, лимиты,
  throttle, honeypot, crawlers.ai, модель). Новая перезагружаемая настройка —
  сюда и в `VerdictSet::Build`; в `OnProxyRequest` — через `verdicts_`
  (снапшот на запрос), не через `context_.config`.
- `src/events/` — JSON-события и NATS-публикатор (свой поток и очередь).
  В событиях никогда нет полного IP, query-строк и значений cookie.
- `src/config/` — YAML-конфиг; неизвестные ключи — ошибка. Новый ключ: поле в
  `Config`, разбор в `config.cc`, тест в `config_test.cc`, описание в
  `deploy/bot-shield.yaml`.
- `ui/` — веб-консоль (ADR-017), один npm-пакет, версии точные
  (`.npmrc`: `save-exact`). `shared/` — контракт API (схемы zod, их же
  проверяет BFF и берёт SPA). `server/` — BFF на Hono: `auth/` (scrypt,
  TOTP, сессии в памяти, `signin` — блокировка перебора и проверка кода,
  `passkeys` — файл ключей WebAuthn и одноразовые challenge), `app.ts` (CSP, сессия, CSRF:
  `X-CSRF-Token` + `Origin`), `roles.ts`, `gateway/` (admin-сокет только
  белым списком вызовов, полный IP отбрасывается схемой; `/metrics`),
  `analytics/` (ClickHouse: только параметризованные запросы из `sql.ts`),
  `audit.ts` (JSONL с цепочкой SHA-256, откат), `routes/`, `dev/` (моки:
  шлюз в памяти и синтетический трафик — только для разработки и тестов).
  `src/` — SPA: `design/tokens.ts` — единственный источник значений из
  дизайна (`tokens.css` генерируется, тест сверяет), `ui/` примитивы,
  `domain/` доменные компоненты, `screens/`, `app/` (роутер, оболочка,
  ⌘K), `lib/` (запросы TanStack Query, форматирование, чистая логика).
  Новый экран: маршрут в `app/router.tsx` (параметры — схема в
  `app/search.ts`), эндпоинт в `server/routes/` + схема в `shared/api.ts`.
  Выдуманных данных в коде нет: чего нет в шлюзе — не показывается.
  Комментарии и тексты интерфейса — на английском.

Инварианты, которые легко сломать:

- Модель — thread-per-core: каждое соединение живёт на одном `io_context`
  своего воркера. `Watchdog` и состояние соединения не потокобезопасны.
- Тайм-ауты делаются через `ScopedWatchdog`, который закрывает сокет; его
  колбэк ссылается на объекты кадра корутины, поэтому watchdog обязан жить
  в той же области видимости.
- nghttp2 нельзя вызывать повторно из его же колбэков: запись только через
  `H2Connection::Flush()` (отложенный проход). Байты тела подтверждаются
  (`consume`) только после передачи дальше — так работает backpressure.
  Каждый полученный байт ответа апстрима должен вернуться в окно, как бы
  ни кончился обмен: прочитан после закрытия потока (`response_consumed`
  живёт дольше потока), выброшен отменой или локальным ответом
  (`Exchange::DiscardResponseBody`). Потерянный кредит навсегда душит
  пул-соединение для всех клиентов.
- Клиентские `X-Forwarded-*`, `X-Real-IP`, `Forwarded`, `X-Bot-*` всегда
  вырезаются (`FilterRequestHeaders`): Traefik доверяет им от шлюза.
- Пассивные разборщики (`H1Tap`, `H2Tap`) только читают копию потока и при
  любой проблеме отключаются; они не могут повлиять на проксирование.
- Всё, что шлюз не может корректно обслужить, уходит в Traefik
  (passthrough), а не закрывается: добавление шлюза не должно ломать сайты.
  Исключение — ClientHello без SNI (`no_sni: reject`): Traefik
  маршрутизирует passthrough по `Host`, это обход проверок (раздел 11.1).
- Защита самого шлюза (тайм-ауты заголовков, `pending_per_ip`, лимиты
  nghttp2, `max_requests_per_connection`) описана в разделе 11.1
  `docs/architecture.md`; новые лимиты — с e2e-проверкой.
- Горячий путь без синхронного сетевого I/O и без глобальных блокировок
  (кроме взятия снапшотов). Всё сетевое (siteverify, ключи Web Bot Auth,
  загрузки) — в фоновых потоках; запрос только читает кеш.
- Консоль не видит полный IP: из `/decisions` BFF оставляет только
  `ip_prefix`/`ip_hash`, браузер не ходит ни в admin-сокет, ни в ClickHouse.
  Изменяющий маршрут BFF — с `requireRole('operator')` и записью в аудит.
  Исключение — свои passkeys (`routes/passkeys.ts`): любая роль, но
  добавление только после повторного пароля и кода, и тоже в аудит.

## Git

- Работа и коммиты прямо в `main`, свои ветки не создавать.
- Никакой атрибуции ИИ: без `Co-Authored-By: Claude`, без «Generated with
  Claude Code» — ни в коммитах, ни в PR.
