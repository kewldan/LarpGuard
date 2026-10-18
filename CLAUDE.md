# bot-shield

Self-hosted шлюз фильтрации ботов перед Traefik. Основной метод — отпечатки
клиента (TCP, TLS, HTTP/2, JS) и их согласованность с тем, кем клиент себя
заявляет. Архитектура, ADR и этапы: `docs/architecture.md` — читать перед
крупными изменениями, решения там приняты и обоснованы.

Готовы M0 (TLS-фронт с маршрутизацией по ClientHello, сертификаты из
`acme.json`, TLS-туннель до Traefik с PROXY v2) и M1 (пассивные отпечатки
TCP/JA4/HTTP2/заголовков, события в NATS → ClickHouse). Следующий этап — M2:
HTTP-aware прокси (ADR-015), вердикты (библиотека отпечатков, скоринг,
shadow/enforce, `X-Bot-*`) и правила на своём языке (ADR-008) сделаны.
M3 готов: rate limiting (`src/ratelimit/`), docker-лейблы (`src/docker/`),
admin API (`src/admin/`). M4 готов: JS-челлендж + PoW и токены
(`src/challenge/`), проверка краулеров по rDNS и политика AI-краулеров
(`src/crawler/`). M5 готов: fail-open (`src/watchdog/`),
поведение и honeypot (`src/behavior/`), tarpit/decoy (`src/action/`),
кластеры в ClickHouse (`tools/cluster_candidates.py`). M6 готов: модель-сигнал
(`src/model/`, `tools/train_model.py`), gRPC через пул, HTTP/3 (`src/quic/`).
UI отложен.

## Команды

```bash
cmake -S . -B build -G Ninja          # первый configure качает зависимости
cmake --build build
ctest --test-dir build --output-on-failure
python3 -I tests/e2e/run_e2e.py build/src/bot-shield   # нужен curl с HTTP/2
cmake --build build --target format        # clang-format на месте
cmake --build build --target format-check
cmake --build build --target tidy          # clang-tidy, должно быть 0 предупреждений
```

Санитайзеры: отдельный каталог `build-asan` с
`-DBOT_SHIELD_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug`, на macOS запускать с
`ASAN_OPTIONS=detect_leaks=0`.

Linux-проверка (`SO_REUSEPORT` с несколькими воркерами, `TCP_SAVED_SYN`
работают только там) — в контейнере `debian:trixie` с `build-essential cmake
ninja-build git python3 openssl`, исходники монтировать read-only.

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
- Комментарии и сообщения в коде — на английском; документация
  (`docs/`, `README.md`) — на русском.
- Зависимости фиксированы в `cmake/dependencies.cmake` (FetchContent,
  точные версии). Новые — так же, без системных пакетов.

## Устройство

- `src/tls/` — разбор ClientHello, хранилище сертификатов, опрос `acme.json`.
- `src/net/` — классификатор маршрута, PROXY v2, `PrefixedStream`,
  `Watchdog`, сокетные опции.
- `src/server/` — обработчики соединений, воркеры, `/metrics` и `/health`
  (503, если `Heartbeats` воркера устарел).
  `ConnectionObserver` в `connection.cc` собирает отпечатки и шлёт события.
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
  изнутри них же; запись пакетов только через `Flush()`. Удаление
  соединения отложено (`Remove` через `post`): оно может быть внутри своего
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
- `src/admin/` — admin API на unix-сокете (`server`), оперативные списки
  (`lists`: главнее правил, allow побеждает block) и журнал решений
  (`decision_log`), режим «под атакой» (`attack`: челлендж всем без
  токена, admin API и `attack.auto_rps`). Новый эндпоинт — в
  `HandleAdminRequest` + тест в `admin_test.cc`.
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
- `src/events/` — JSON-события и NATS-публикатор (свой поток и очередь).
  В событиях никогда нет полного IP, query-строк и значений cookie.
- `src/config/` — YAML-конфиг; неизвестные ключи — ошибка. Новый ключ: поле в
  `Config`, разбор в `config.cc`, тест в `config_test.cc`, описание в
  `deploy/bot-shield.yaml`.

Инварианты, которые легко сломать:

- Модель — thread-per-core: каждое соединение живёт на одном `io_context`
  своего воркера. `Watchdog` и состояние соединения не потокобезопасны.
- Тайм-ауты делаются через `ScopedWatchdog`, который закрывает сокет; его
  колбэк ссылается на объекты кадра корутины, поэтому watchdog обязан жить
  в той же области видимости.
- nghttp2 нельзя вызывать повторно из его же колбэков: запись только через
  `H2Connection::Flush()` (отложенный проход). Байты тела подтверждаются
  (`consume`) только после передачи дальше — так работает backpressure.
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
  (кроме взятия снапшота сертификатов).

## Git

- Работа и коммиты прямо в `main`, свои ветки не создавать.
- Никакой атрибуции ИИ: без `Co-Authored-By: Claude`, без «Generated with
  Claude Code» — ни в коммитах, ни в PR.
