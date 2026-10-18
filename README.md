# bot-shield

Self-hosted шлюз для фильтрации ботов, скреперов и прочей автоматизации по
отпечаткам клиента (TCP, TLS, HTTP/2, JS) с rate limiting. Встаёт перед
существующим Traefik без правок его роутеров и лейблов контейнеров.

Архитектура, ADR и план этапов: [docs/architecture.md](docs/architecture.md).

## Статус: M6 готов

Шлюз встаёт перед Traefik и терминирует TLS для хостов с сертификатом в
`acme.json`; остальное пропускает как есть. Терминированный трафик
обрабатывается полноценным HTTP-прокси, снимаются отпечатки, события уходят
в NATS → ClickHouse. Каждый запрос получает оценку по согласованности
User-Agent со стеком клиента (TLS, HTTP/2, TCP); в режиме shadow оценка
только передаётся в Traefik заголовками `X-Bot-*`, в enforce — боты
блокируются или получают JS-челлендж (режим включается по хостам).

- Маршрутизация по ClientHello: terminate, passthrough (неизвестный SNI,
  `acme-tls/1`, `passthrough_hosts`) или reject; сертификаты из `acme.json`
  с перезагрузкой.
- HTTP-прокси: HTTP/1.1 и HTTP/2 к клиенту, пул HTTP/2-соединений к Traefik,
  WebSocket, потоковые тела с управлением потоком, реальный IP в
  `X-Forwarded-For` (подделка от клиента вырезается), `502` при недоступном
  Traefik. Passthrough и порт 80 — с PROXY protocol v2.
- Отпечатки: TCP SYN (Linux), JA4, HTTP/2 (Akamai), порядок заголовков;
  JA4T/JA4H опционально (`BOT_SHIELD_FOXIO`, см. `src/fp/foxio/LICENSE.md`).
- Вердикты: библиотека отпечатков `deploy/fingerprints.yaml` (встроена),
  скоринг с причинами, `mode: shadow|enforce` и `policy.hosts`, правила
  `allow` / `challenge` / `block` / `score` на своём языке условий (раздел 6.1
  архитектуры).
- JS-челлендж: страница с проверкой сигналов браузера и proof-of-work,
  stateless-токен `__bs` (HMAC, привязка к JA4 и подсети, ротация ключей),
  который снижает скор; JSON-ответ для XHR; cookie не доходит до приложения.
- Краулеры: проверка поисковиков по reverse + forward DNS (класс
  `verified_bot`, подделки получают `fake_crawler`), политика AI-краулеров
  (`crawlers.ai: allow|challenge|block`).
- Политики через docker-лейблы `botshield.*`: режим (shadow/enforce/off),
  passthrough и лимиты для хостов контейнера, без перезапуска.
- Admin API на unix-сокете: статус, итоговая политика хоста, оперативные
  allow/block-списки с TTL, журнал последних решений по `X-Bot-Request-Id`.
- Rate limiting: GCRA с составными ключами (IP, подсеть, отпечаток, API-ключ,
  cookie), фильтрами по хостам/путям/методам/классу, `429` с `Retry-After`;
  лимиты соединений на IP до TLS.
- Поведение клиентов (регулярные интервалы, 404, API без страницы, страницы
  без статики, перебор ID) и пути-ловушки (`/.env`, `/.git/*`, …), метящие
  адрес и отпечаток.
- Действия `tarpit` (очень медленный ответ) и `decoy` (фальшивые данные с
  водяным знаком, который пишется в событие).
- Кластеры отпечатков с аномалиями в ClickHouse и `tools/cluster_candidates.py`,
  который предлагает записи для библиотеки отпечатков.
- Модель-сигнал: градиентный бустинг на деревьях, обучаемый
  `tools/train_model.py` на событиях из ClickHouse (слабые метки: honeypot,
  известная автоматизация, решённый челлендж) и вычисляемый в шлюзе.
- HTTP/3 на входе (ngtcp2 + nghttp3): те же вердикты, что по TCP, JA4 для
  QUIC и отпечаток transport parameters, Retry против поддельных адресов.
- Fail-open: heartbeat воркеров, systemd watchdog и `bot-shield-watchdog`,
  который при отказе шлюза направляет трафик прямо в Traefik.
- События `conn` и `req` (со статусом, длительностью и вердиктом) в NATS без полных IP
  и query-строк; схема ClickHouse — `deploy/clickhouse/`.

## Сборка

Нужны CMake ≥ 3.28, компилятор с C++20 и доступ в сеть при первом configure:
BoringSSL, Asio, yaml-cpp, nlohmann/json и GoogleTest скачиваются
фиксированных версий.

```bash
cmake -S . -B build -G Ninja
```

```bash
cmake --build build
```

## Тесты

```bash
ctest --test-dir build --output-on-failure
```

Сквозной тест против фейкового Traefik (нужны `python3`, `openssl` и
`curl` с HTTP/2):

```bash
python3 tests/e2e/run_e2e.py build/src/bot-shield
```

Сборка с санитайзерами: `-DBOT_SHIELD_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug`.
Без JA4T/JA4H (FoxIO License): `-DBOT_SHIELD_FOXIO=OFF`.

## Стиль и статический анализ

Код следует Google C++ Style Guide: `.clang-format` (`BasedOnStyle: Google`) и
`.clang-tidy` (bugprone, google, modernize, performance и правила именования).

```bash
cmake --build build --target format-check
```

```bash
cmake --build build --target tidy
```

`--target format` переформатирует исходники на месте, а
`-DBOT_SHIELD_CLANG_TIDY=ON` включает clang-tidy прямо при компиляции.

## Запуск

```bash
build/src/bot-shield --config deploy/bot-shield.yaml --check-config
```

Развёртывание рядом с Traefik описано в `deploy/`:

- `bot-shield.yaml` — конфиг шлюза со всеми ключами и значениями по умолчанию;
- `traefik.yml` — единственная правка в Traefik: entrypoint'ы переезжают на
  :8443/:8080 и получают `proxyProtocol.trustedIPs` и
  `forwardedHeaders.trustedIPs`;
- `failopen/` — nftables-таблица, которая закрывает :8443/:8080 снаружи
  (загружать при старте системы, без неё Traefik открыт в обход шлюза), и
  правила fail-open для `bot-shield-watchdog`;
- `systemd/` — units шлюза (`Type=notify`, `WatchdogSec`) и watchdog;
- `docker-compose.yml` — Traefik, bot-shield и watchdog в host network, опционально
  NATS и ClickHouse для аналитики;
- `clickhouse/schema.sql` — таблицы событий и агрегатов.

HTTP/3 в Traefik должен оставаться выключенным, иначе QUIC пойдёт в обход
шлюза. HTTP/3 принимает сам шлюз (`http3.enabled` в `bot-shield.yaml`, UDP на
порту HTTPS).
