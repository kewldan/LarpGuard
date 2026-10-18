<div align="center">

# 🛡️ bot-shield

**A self-hosted bot-filtering gateway that sits in front of Traefik.**

It looks at how a client really talks (TCP, TLS, HTTP/2, HTTP/3, JS) and
checks that against what the client says it is.

![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white)
![BoringSSL](https://img.shields.io/badge/TLS-BoringSSL-4285F4)
![HTTP/1.1 · HTTP/2 · HTTP/3](https://img.shields.io/badge/HTTP-1.1%20%C2%B7%202%20%C2%B7%203-success)
![Traefik](https://img.shields.io/badge/works%20with-Traefik-24A1C1?logo=traefikproxy&logoColor=white)
![Status](https://img.shields.io/badge/status-M6%20done-brightgreen)

</div>

---

A scraper can copy Chrome's `User-Agent` string in one line of code.
Copying Chrome's TLS ClientHello, HTTP/2 settings frame, header order and
TCP SYN all at once is much harder. bot-shield fingerprints every layer of
the connection and asks one question: **does this stack match the browser
it claims to be?**

You don't touch your Traefik routers or container labels. The gateway takes
over ports 443/80, and Traefik moves to loopback behind it.

## ✨ Highlights

- 🔍 **Fingerprints at every layer.** TCP SYN (Linux), JA4, HTTP/2
  (Akamai format), header order, QUIC transport parameters. JA4T/JA4H are
  optional.
- 🧠 **Consistency scoring.** Each signal adds a weight and a reason code.
  Requests are classed `human`, `suspicious`, `bot` or `verified_bot`.
  Traefik receives the verdict in `X-Bot-*` headers.
- 👀 **Shadow mode first.** Score and log everything, act on nothing. Then
  switch to `enforce` per host, from YAML or a Docker label.
- 🧩 **JS challenge and proof-of-work.** Tokens (`__bs`) are stateless and
  HMAC-signed, bound to the JA4 and subnet, with rotating keys. The cookie
  never reaches your app.
- 🤖 **Crawler verification.** Search engines are verified with reverse and
  forward DNS. Impostors get `fake_crawler`. AI crawlers follow their own
  `allow`, `challenge` or `block` policy.
- 📜 **Rule language.** Write conditions like
  `path ~ "/admin*" and class != "human"`. Types are checked when the config
  loads.
- 🚦 **Rate limiting.** GCRA with composite keys: IP, subnet, fingerprint,
  API key, cookie or session. Filters by host, path, method and class.
  Per-IP connection limits apply before TLS.
- 🍯 **Honeypots and behaviour.** Trap paths such as `/.env` and `/.git/*`,
  robotic timing, 404 storms, ID enumeration, API calls without the page.
- 🐢 **More than block.** Other actions are `challenge`, `throttle`,
  `tarpit` (a response that trickles out) and `decoy` (fake data with a
  watermark you can trace later).
- 🌲 **Built-in ML signal.** Gradient-boosted trees are trained on your own
  ClickHouse events with weak labels and evaluated in C++ in microseconds.
  No ONNX runtime.
- ⚡ **HTTP/3 at the edge.** Built on ngtcp2 and nghttp3, with the same
  verdicts as TCP, Retry tokens and QUIC JA4.
- 🔌 **gRPC works.** Requests go through a pooled HTTP/2 upstream to
  Traefik, including streaming and trailers-only responses.
- 🐳 **Docker labels.** `botshield.mode`, `botshield.ratelimit.*`,
  `botshield.challenge.paths` and more. Changes apply without a restart.
- 🔥 **Hot reload.** `SIGHUP` or `POST /reload` swaps the fingerprint
  library, policy, rules, limits and model atomically. A broken config is
  never applied.
- 🧯 **Fail-open.** Workers send heartbeats, systemd runs a watchdog, and
  nftables redirects traffic straight to Traefik if the gateway dies. Adding
  bot-shield should never take your sites down.
- 📊 **Analytics.** Connection and request events go to NATS and then
  ClickHouse. They never contain full IPs, query strings or cookie values.
  Anomaly clusters suggest new library entries.

## 🏗️ How it fits

```text
                    ┌──────────────────────── bot-shield ────────────────────────┐
 client ── :443 ──▶ │ ClientHello ─▶ terminate ─▶ fingerprints ─▶ score ─▶ rules │ ──▶ Traefik :8443 ──▶ apps
  (TCP / QUIC)      │      │                                          │          │     (HTTP/2 pool,
                    │      └─▶ passthrough (unknown SNI, acme-tls/1)  ▼          │      X-Forwarded-For,
                    │                         allow · challenge · throttle ·     │      X-Bot-*)
 client ── :80 ───▶ │ passthrough + PROXY v2  tarpit · decoy · block            │ ──▶ Traefik :8080
                    └────────────┬───────────────────────────────────────────────┘
                                 └─▶ NATS ─▶ ClickHouse ─▶ clusters · model training
```

- **Thread-per-core.** One `asio` event loop per worker, with
  `SO_REUSEPORT` on TCP and UDP. The hot path takes no global locks and does
  no synchronous network I/O.
- **Certificates come from Traefik's `acme.json`.** It is polled and
  reloaded. Hosts without a certificate pass through untouched.
- **Anything the gateway can't serve correctly goes to Traefik** instead of
  failing.

## 🚀 Quick start

**Requirements:** CMake ≥ 3.28, a C++20 compiler, and network access on the
first configure. Pinned dependencies are fetched automatically: BoringSSL,
Asio, nghttp2, ngtcp2, nghttp3, llhttp, yaml-cpp, nlohmann/json and
GoogleTest.

```bash
cmake -S . -B build -G Ninja
```

```bash
cmake --build build
```

```bash
build/src/bot-shield --config deploy/bot-shield.yaml --check-config
```

Or build the container image (it includes `bot-shield-watchdog` and
nftables):

```bash
docker build -t bot-shield .
```

### 📦 Deploying next to Traefik

Everything you need is in [`deploy/`](deploy):

| File | What it is |
|------|------------|
| `bot-shield.yaml` | Gateway config with every key and its default |
| `traefik.yml` | The only Traefik change: entrypoints move to `:8443`/`:8080` and trust PROXY v2 and `X-Forwarded-*` from the gateway |
| `docker-compose.yml` | Traefik, bot-shield and the watchdog in host network, plus optional NATS and ClickHouse |
| `failopen/` | nftables table that closes `:8443`/`:8080` from outside (load it at boot), and the fail-open redirect rules |
| `systemd/` | Units for the gateway (`Type=notify`, `WatchdogSec`) and the watchdog |
| `clickhouse/schema.sql` | Event tables, aggregates and cluster views |
| `fingerprints.yaml` | Fingerprint library and signal weights |

> [!IMPORTANT]
> Keep HTTP/3 **off in Traefik**, or QUIC traffic will bypass the gateway.
> Let bot-shield accept it instead: set `http3.enabled: true`.

> [!TIP]
> Start with `mode: shadow`. Watch `X-Bot-Score`, `X-Bot-Class` and
> `X-Bot-Reasons` in your logs or ClickHouse for a while, then switch busy
> hosts to `enforce`.

## ⚙️ Configuration at a glance

```yaml
mode: shadow                  # shadow | enforce
policy:
  hosts:
    shop.example.com: enforce

rules:
  - name: monitoring
    when: 'cidr("10.0.0.0/8") and header("x-monitor") == "1"'
    action: allow
  - name: admin-scrapers
    when: 'path ~ "/admin*" and class != "human"'
    action: block
  - name: mobile-app
    when: 'ua_tool == "okhttp" and host == "api.example.com"'
    action: score
    score: -40

crawlers:
  ai: challenge               # default | allow | challenge | block

http3:
  enabled: true
```

Or set policy per container with labels:

```yaml
labels:
  botshield.mode: enforce
  botshield.ratelimit.login: "rate=5/m key=ip path=/login methods=POST"
  botshield.challenge.paths: "/checkout*,/login"
  botshield.ai_crawlers: block
```

Unknown config keys are errors, so typos never pass silently.

## 🎛️ Operating it

The admin API listens on a unix socket (mode 0600). It has no TCP port.

```bash
curl --unix-socket /run/bot-shield/admin.sock http://bot-shield/status
```

| Endpoint | Purpose |
|----------|---------|
| `GET /status` | Workers, connections, verdict generation |
| `GET /policy?host=…` | The effective policy for a host |
| `/lists` | Allow and block lists with TTLs (they win over rules) |
| `GET /decisions/<id>` | Why a request was decided this way (from `X-Bot-Request-Id`) |
| `/attack` | Under-attack mode: challenge everyone without a token |
| `POST /reload` | Hot-reload verdict settings |

Prometheus metrics and `/health` are served on `127.0.0.1:9900`.
`/health` returns 503 when a worker loop stalls.

## 🧪 Development

```bash
ctest --test-dir build --output-on-failure
```

The end-to-end suite runs against a fake Traefik. It needs `python3`,
`openssl` and a `curl` with HTTP/2:

```bash
python3 -I tests/e2e/run_e2e.py build/src/bot-shield
```

```bash
cmake --build build --target format-check
```

```bash
cmake --build build --target tidy
```

- **Style.** Google C++ Style, enforced by `clang-format` and
  `clang-tidy`. `tidy` must report 0 warnings.
- **Sanitizers.** Build with `-DBOT_SHIELD_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug`.
- **Linux-only paths** (`TCP_SAVED_SYN`, multi-worker `SO_REUSEPORT`). Test
  them in a `debian:trixie` container.
- **No JA4T/JA4H** (FoxIO License): build with `-DBOT_SHIELD_FOXIO=OFF`.
- **Retrain the model** from ClickHouse events with `tools/train_model.py`.
- **Find new fingerprint clusters** with `tools/cluster_candidates.py`.

## 🗂️ Layout

```text
src/
├── tls/        ClientHello parsing, certificate store, acme.json watcher
├── net/        route classifier, PROXY v2, socket options, timeouts
├── server/     workers, connection handlers, verdict pipeline, /metrics, /health
├── proxy/      HTTP/1.1 + HTTP/2 server side, HTTP/2 upstream pool to Traefik
├── quic/       HTTP/3 server (ngtcp2 + nghttp3)
├── fp/         fingerprints and passive HTTP taps (fp/foxio: JA4T/JA4H)
├── score/      scorer, rule language, shadow/enforce policy
├── challenge/  JS challenge, proof-of-work, clearance tokens
├── crawler/    crawler catalogue and rDNS verifier
├── behavior/   behaviour signals and honeypot marks
├── action/     tarpit and decoy responses
├── ratelimit/  GCRA, sharded store, limit keys
├── model/      feature extraction and GBDT evaluation
├── docker/     Docker API client and botshield.* labels
├── admin/      admin API, lists, decision log, under-attack mode
├── events/     JSON events and the NATS publisher
├── watchdog/   bot-shield-watchdog (fail-open)
└── config/     strict YAML config
```

## 📚 Docs

The architecture, ADRs, the full signal catalogue and the milestone history
are in [`docs/architecture.md`](docs/architecture.md). That document is in
Russian.

## 🗺️ Roadmap

- [x] **M0**: TLS front, routing by ClientHello, certificates from `acme.json`
- [x] **M1**: passive fingerprints, events to NATS and ClickHouse
- [x] **M2**: HTTP-aware proxy, verdicts, rule language
- [x] **M3**: rate limiting, Docker labels, admin API
- [x] **M4**: JS challenge and PoW, crawler verification
- [x] **M5**: fail-open, behaviour and honeypots, tarpit and decoy, clusters
- [x] **M6**: ML signal, gRPC, HTTP/3
- [ ] Web UI
- [ ] Canvas, WebGL and audio probes in the challenge; CAPTCHA plugin
- [ ] Crawler IP ranges and Web Bot Auth
- [ ] ASN rate-limit key, XDP pre-filter
