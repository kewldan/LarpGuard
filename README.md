# bot-shield

Self-hosted шлюз для фильтрации ботов, скреперов и прочей автоматизации по
отпечаткам клиента (TCP, TLS, HTTP/2, JS) с rate limiting. Встаёт перед
существующим Traefik без правок его роутеров и лейблов контейнеров.

Архитектура, ADR и план этапов: [docs/architecture.md](docs/architecture.md).

## Статус: M1

Шлюз встаёт перед Traefik, терминирует TLS для хостов с сертификатом в
`acme.json` и пропускает остальное как есть (M0). С M1 он снимает пассивные
отпечатки и отправляет события в NATS → ClickHouse. Решений «бот / не бот»
пока нет — они появятся в M2.

- Маршрутизация по ClientHello: terminate, passthrough (неизвестный SNI,
  `acme-tls/1`, `passthrough_hosts`) или reject; сертификаты из `acme.json`
  с перезагрузкой; PROXY protocol v2 к Traefik; HTTP/1.1, HTTP/2, WebSocket.
- Отпечатки: TCP SYN (Linux), JA4, HTTP/2 (Akamai), порядок заголовков;
  JA4T/JA4H опционально (`BOT_SHIELD_FOXIO`, см. `src/fp/foxio/LICENSE.md`).
- События `conn` и `req` в NATS (JSON) без полных IP и query-строк; схема
  ClickHouse с почасовой агрегацией по отпечаткам — `deploy/clickhouse/`.
- Воркеры thread-per-core, `/metrics` и `/health`, graceful drain.

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

Сквозной тест против фейкового Traefik (нужны `python3` и `openssl`):

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
  loopback и получают `proxyProtocol.trustedIPs`;
- `docker-compose.yml` — Traefik и bot-shield в host network, опционально
  NATS и ClickHouse для аналитики;
- `clickhouse/schema.sql` — таблицы событий и агрегатов.

HTTP/3 в Traefik должен оставаться выключенным, иначе QUIC пойдёт в обход
шлюза.
