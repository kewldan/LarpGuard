# bot-shield

Self-hosted шлюз для фильтрации ботов, скреперов и прочей автоматизации по
отпечаткам клиента (TCP, TLS, HTTP/2, JS) с rate limiting. Встаёт перед
существующим Traefik без правок его роутеров и лейблов контейнеров.

Архитектура, ADR и план этапов: [docs/architecture.md](docs/architecture.md).

## Статус: M0

Пока шлюз прозрачен. Для хостов, сертификат которых есть в `acme.json`
Traefik, он терминирует TLS и пробрасывает трафик в Traefik, всё остальное
передаёт как есть. Отпечатки и решения появятся в M1–M2.

- Читает ClientHello и выбирает маршрут для соединения:
  - terminate — сертификат для SNI известен;
  - passthrough — SNI неизвестен или отсутствует, ALPN `acme-tls/1` или хост
    из `passthrough_hosts`;
  - reject — не TLS или битый ClientHello.
- Берёт сертификаты из `acme.json` и опрашивает его на изменения. Поддерживает
  wildcard; при битом файле продолжает работать на прежних сертификатах.
- На каждое соединение отправляет в Traefik PROXY protocol v2, чтобы тот видел
  реальный IP клиента.
- На плече до Traefik сохраняет ALPN клиента: HTTP/1.1, HTTP/2 и WebSocket
  работают без изменений.
- Воркеры thread-per-core с `SO_REUSEPORT`. На Linux сохраняет TCP SYN.
  Отдаёт `/metrics` для Prometheus и `/health`, по SIGTERM корректно
  дорабатывает открытые соединения.

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

## Запуск

```bash
build/src/bot-shield --config deploy/bot-shield.yaml --check-config
```

Развёртывание рядом с Traefik описано в `deploy/`:

- `bot-shield.yaml` — конфиг шлюза со всеми ключами и значениями по умолчанию;
- `traefik.yml` — единственная правка в Traefik: entrypoint'ы переезжают на
  loopback и получают `proxyProtocol.trustedIPs`;
- `docker-compose.yml` — оба сервиса в host network.

HTTP/3 в Traefik должен оставаться выключенным, иначе QUIC пойдёт в обход
шлюза.
