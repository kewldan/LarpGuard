# bot-shield

Self-hosted шлюз фильтрации ботов перед Traefik. Основной метод — отпечатки
клиента (TCP, TLS, HTTP/2, JS) и их согласованность с тем, кем клиент себя
заявляет. Архитектура, ADR и этапы: `docs/architecture.md` — читать перед
крупными изменениями, решения там приняты и обоснованы.

Сейчас готов M0: TLS-фронт с маршрутизацией по ClientHello (terminate /
passthrough / reject), сертификаты из `acme.json` Traefik, TLS-туннель до
Traefik с PROXY protocol v2. Следующий этап — M1 (пассивные отпечатки, события).

## Команды

```bash
cmake -S . -B build -G Ninja          # первый configure качает зависимости
cmake --build build
ctest --test-dir build --output-on-failure
python3 -I tests/e2e/run_e2e.py build/src/bot-shield
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
- `src/server/` — обработчики соединений, воркеры, `/metrics`.
- `src/config/` — YAML-конфиг; неизвестные ключи — ошибка. Новый ключ: поле в
  `Config`, разбор в `config.cc`, тест в `config_test.cc`, описание в
  `deploy/bot-shield.yaml`.

Инварианты, которые легко сломать:

- Модель — thread-per-core: каждое соединение живёт на одном `io_context`
  своего воркера. `Watchdog` и состояние соединения не потокобезопасны.
- Тайм-ауты делаются через `ScopedWatchdog`, который закрывает сокет; его
  колбэк ссылается на объекты кадра корутины, поэтому watchdog обязан жить
  в той же области видимости.
- Всё, что шлюз не может корректно обслужить, уходит в Traefik
  (passthrough), а не закрывается: добавление шлюза не должно ломать сайты.
- Горячий путь без синхронного сетевого I/O и без глобальных блокировок
  (кроме взятия снапшота сертификатов).

## Git

- Работа и коммиты прямо в `main`, свои ветки не создавать.
- Никакой атрибуции ИИ: без `Co-Authored-By: Claude`, без «Generated with
  Claude Code» — ни в коммитах, ни в PR.
