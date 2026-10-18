#!/usr/bin/env python3
"""End-to-end test: runs the bot-shield binary in front of a fake Traefik.

The fake Traefik (tests/e2e/fake_upstream.cc) speaks HTTP/2 to the gateway's
upstream pool and answers with a JSON description of each request; on
passthrough connections it answers one line per connection instead. Gateway
and upstream certificates differ, so a client can tell whether bot-shield
terminated TLS (the gateway certificate validates) or passed it through.
Events go to a fake NATS server and are checked too.

Usage: run_e2e.py path/to/bot-shield [path/to/bot_shield_fake_upstream]
"""

import base64
import http.client
import json
import os
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


def find_openssl():
    for candidate in ("/opt/homebrew/opt/openssl@3/bin/openssl",
                      "/usr/local/opt/openssl@3/bin/openssl", "openssl"):
        path = shutil.which(candidate)
        if path:
            return path
    sys.exit("openssl not found")


def make_cert(workdir, name, dns_names):
    cert = os.path.join(workdir, name + ".crt")
    key = os.path.join(workdir, name + ".key")
    san = ",".join("DNS:" + n for n in dns_names)
    subprocess.run([
        find_openssl(), "req", "-x509", "-newkey", "ec", "-pkeyopt",
        "ec_paramgen_curve:P-256", "-nodes", "-keyout", key, "-out", cert,
        "-days", "2", "-subj", "/CN=" + dns_names[0], "-addext",
        "subjectAltName=" + san
    ], check=True, capture_output=True)
    return cert, key


def acme_json(certs):
    entries = []
    for cert, key, main in certs:
        with open(cert, "rb") as c, open(key, "rb") as k:
            entries.append({
                "domain": {"main": main},
                "certificate": base64.b64encode(c.read()).decode(),
                "key": base64.b64encode(k.read()).decode(),
                "Store": "default",
            })
    return json.dumps({"le": {"Account": {}, "Certificates": entries}})


def write_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(data)
    os.replace(tmp, path)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not open")


class FakeNats:
    """Minimal NATS server: INFO, PING/PONG, collects PUB payloads as JSON."""

    def __init__(self):
        self.port = free_port()
        self.events = []
        self.lock = threading.Lock()
        listener = socket.create_server(("127.0.0.1", self.port))
        threading.Thread(target=self._accept, args=(listener,),
                         daemon=True).start()

    def _accept(self, listener):
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    def _serve(self, conn):
        conn.sendall(b'INFO {"server_id":"e2e","max_payload":1048576}\r\n')
        reader = conn.makefile("rb")
        while True:
            line = reader.readline()
            if not line:
                return
            line = line.rstrip(b"\r\n")
            if line == b"PING":
                conn.sendall(b"PONG\r\n")
            elif line.startswith(b"PUB "):
                _, subject, size = line.split(b" ")
                payload = reader.read(int(size))
                reader.read(2)
                with self.lock:
                    self.events.append((subject.decode(),
                                        json.loads(payload)))

    def find(self, subject, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                for event_subject, event in self.events:
                    if event_subject == subject and predicate(event):
                        return event
            time.sleep(0.05)
        raise AssertionError(f"no matching {subject} event")

    def payloads(self):
        with self.lock:
            return [json.dumps(event) for _, event in self.events]


def parse_reply(reply):
    return dict(item.split("=", 1) for item in reply.strip().split(" "))


def tls_socket(port, server_name, cafile, alpn=None):
    context = ssl.create_default_context(cafile=cafile)
    if alpn:
        context.set_alpn_protocols(alpn)
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    return context.wrap_socket(raw, server_hostname=server_name)


def line_request(port, server_name, cafile, alpn=None, payload=b"hello\n"):
    """Passthrough probe: one line to the fake Traefik's line mode."""
    with tls_socket(port, server_name, cafile, alpn) as tls:
        local_port = tls.getsockname()[1]
        negotiated = tls.selected_alpn_protocol()
        tls.sendall(payload)
        reply = tls.recv(4096).decode()
    return parse_reply(reply), local_port, negotiated


class _KeepOpen:
    """A reader http.client cannot close (it closes after each response)."""

    def __init__(self, reader):
        self.reader = reader

    def __getattr__(self, name):
        return getattr(self.reader, name)

    def close(self):
        pass


class _Buffered:
    """Lets several http.client responses share one buffered reader."""

    def __init__(self, reader):
        self.reader = _KeepOpen(reader)

    def makefile(self, *args, **kwargs):
        return self.reader


def h1_exchange(port, server_name, cafile, raw, responses=1,
                alpn=("http/1.1",)):
    """Sends raw HTTP/1.1 bytes, returns [(status, headers, body)]."""
    results = []
    with tls_socket(port, server_name, cafile, list(alpn)) as tls:
        tls.sendall(raw)
        reader = tls.makefile("rb")
        for _ in range(responses):
            response = http.client.HTTPResponse(_Buffered(reader))
            response.begin()
            body = response.read()
            results.append((response.status,
                            {k.lower(): v for k, v in response.getheaders()},
                            body))
    return results


def h1_get(port, server_name, cafile, path, extra=b""):
    raw = (f"GET {path} HTTP/1.1\r\nHost: {server_name}\r\n".encode() + extra +
           b"\r\n")
    return h1_exchange(port, server_name, cafile, raw)[0]


def curl(port, host, cafile, path, output, extra=()):
    result = subprocess.run(
        ["curl", "-sS", "--http2", "--resolve", f"{host}:{port}:127.0.0.1",
         "--cacert", cafile, "-o", output, "-w",
         "%{http_code} %{http_version}", *extra,
         f"https://{host}:{port}{path}"],
        capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise AssertionError(f"curl failed: {result.stderr}")
    status, version = result.stdout.split()
    return int(status), version


class Checks:
    def __init__(self):
        self.failed = 0

    def run(self, name, fn):
        try:
            fn()
            print(f"PASS {name}")
        except Exception as e:  # noqa: BLE001
            self.failed += 1
            print(f"FAIL {name}: {e!r}")


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    binary = os.path.abspath(sys.argv[1])
    fake = (os.path.abspath(sys.argv[2]) if len(sys.argv) == 3 else
            os.path.join(os.path.dirname(binary), "..", "tests",
                         "bot_shield_fake_upstream"))
    version = subprocess.run([binary, "--version"], capture_output=True,
                             text=True, check=True).stdout
    ja4plus = "(ja4plus)" in version
    workdir = tempfile.mkdtemp(prefix="bot-shield-e2e-")

    gw_a = make_cert(workdir, "gw-a", ["a.test", "www.a.test", "noh2.test"])
    gw_w = make_cert(workdir, "gw-w", ["*.w.test"])
    gw_c = make_cert(workdir, "gw-c", ["c.test"])
    upstream = make_cert(workdir, "upstream",
                         ["a.test", "b.test", "c.test", "grpc.a.test",
                          "noh2.test", "x.w.test", "www.a.test"])
    acme_path = os.path.join(workdir, "acme.json")
    write_atomic(acme_path, acme_json([(*gw_a, "a.test"), (*gw_w, "*.w.test")]))

    tls_port, plain_port = free_port(), free_port()
    upstream_process = subprocess.Popen(
        [fake, str(tls_port), str(plain_port), *upstream])
    wait_port(tls_port)
    nats = FakeNats()

    https_port, http_port, metrics_port = free_port(), free_port(), free_port()
    config_path = os.path.join(workdir, "bot-shield.yaml")
    with open(config_path, "w") as f:
        f.write(f"""
listen:
  https: 127.0.0.1:{https_port}
  http: 127.0.0.1:{http_port}
workers: 2
traefik:
  acme_json: {acme_path}
  acme_reload_interval: 200ms
  upstream_https: 127.0.0.1:{tls_port}
  upstream_http: 127.0.0.1:{plain_port}
  pool_size: 2
passthrough_hosts: [grpc.a.test]
mode: shadow
policy:
  hosts:
    www.a.test: enforce
timeouts:
  client_hello: 1s
events:
  nats: nats://127.0.0.1:{nats.port}
  subject_prefix: e2e.events
  ip_salt: e2e-salt
metrics:
  listen: 127.0.0.1:{metrics_port}
log_level: debug
""")

    log_path = os.path.join(workdir, "bot-shield.log")
    log_file = open(log_path, "w")
    process = subprocess.Popen([binary, "--config", config_path],
                               stdout=log_file, stderr=subprocess.STDOUT)
    metrics_url = f"http://127.0.0.1:{metrics_port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(metrics_url + "/health", timeout=1)
            break
        except OSError:
            time.sleep(0.05)
    else:
        process.kill()
        upstream_process.kill()
        sys.exit("bot-shield did not start; log: " + open(log_path).read())

    ca_a, ca_w, ca_c, ca_up = gw_a[0], gw_w[0], gw_c[0], upstream[0]
    checks = Checks()

    # --- Proxy over HTTP/1.1 ------------------------------------------------

    def h1_get_forwarding():
        status, headers, body = h1_get(
            https_port, "a.test", ca_a, "/items/42?x=1",
            b"X-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\n"
            b"X-Bot-Score: 42\r\nUser-Agent: e2e-agent\r\n")
        expect(status == 200, status)
        seen = json.loads(body)
        expect(seen["proto"] == "h2", seen)  # Upstream leg is HTTP/2.
        expect(seen["proxy_src"] == "", seen)  # Pool: no PROXY header.
        h = seen["headers"]
        expect(h[":path"] == "/items/42?x=1", h)
        expect(h[":authority"] == "a.test", h)
        expect(h["x-forwarded-for"] == "127.0.0.1", h)
        expect(h["x-real-ip"] == "127.0.0.1", h)
        expect(h["x-forwarded-proto"] == "https", h)
        expect(h["x-forwarded-host"] == "a.test", h)
        # The client's X-Bot-Score is replaced by the gateway's verdict.
        expect(h["x-bot-score"] != "42", h)
        expect(h["x-bot-mode"] == "shadow", h)
        expect(h["user-agent"] == "e2e-agent", h)
        expect("host" not in h and "connection" not in h, h)
        expect(seen["sni"] == "a.test", seen)

    def h1_keep_alive_and_pipelining():
        raw = b"".join(
            f"GET /p/{i} HTTP/1.1\r\nHost: a.test\r\n\r\n".encode()
            for i in range(3))
        results = h1_exchange(https_port, "a.test", ca_a, raw, responses=3)
        paths = [json.loads(body)["headers"][":path"] for _, _, body in results]
        expect(paths == ["/p/0", "/p/1", "/p/2"], paths)

    def h1_uploads():
        body = os.urandom(3 * 1024 * 1024)
        raw = (b"POST /upload HTTP/1.1\r\nHost: a.test\r\n" +
               f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        status, _, reply = h1_exchange(https_port, "a.test", ca_a, raw)[0]
        expect(status == 200, status)
        expect(json.loads(reply)["body_len"] == len(body), reply[:200])
        chunks = b"".join(f"{4096:x}\r\n".encode() + b"y" * 4096 + b"\r\n"
                          for _ in range(256)) + b"0\r\n\r\n"
        raw = (b"POST /chunked HTTP/1.1\r\nHost: a.test\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n" + chunks)
        status, _, reply = h1_exchange(https_port, "a.test", ca_a, raw)[0]
        expect(json.loads(reply)["body_len"] == 256 * 4096, reply[:200])

    def h1_big_download_and_status():
        status, headers, body = h1_get(https_port, "a.test", ca_a,
                                       "/big?bytes=8388608")
        expect(status == 200 and len(body) == 8388608, (status, len(body)))
        expect(headers.get("content-length") == "8388608", headers)
        status, _, _ = h1_get(https_port, "a.test", ca_a, "/status/404")
        expect(status == 404, status)
        # Trailers force a chunked HTTP/1.1 response.
        status, headers, body = h1_get(https_port, "a.test", ca_a, "/trailers")
        expect(status == 200, status)
        expect(headers.get("transfer-encoding") == "chunked", headers)
        expect(json.loads(body)["proto"] == "h2", body)

    def bad_gateway_when_upstream_fails():
        status, _, body = h1_get(https_port, "noh2.test", ca_a, "/")
        expect(status == 502, (status, body))

    def websocket_tunnel():
        with tls_socket(https_port, "a.test", ca_a, ["http/1.1"]) as tls:
            tls.sendall(b"GET /ws HTTP/1.1\r\nHost: a.test\r\n"
                        b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
                        b"X-Forwarded-For: 6.6.6.6\r\n"
                        b"Sec-WebSocket-Version: 13\r\n"
                        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
            head = b""
            while b"\r\n\r\n" not in head:
                head += tls.recv(4096)
            expect(head.startswith(b"HTTP/1.1 101"), head)
            expect(b"X-Seen-Forwarded-For: 127.0.0.1" in head, head)
            tls.sendall(b"ping-frame")
            echo = b""
            while len(echo) < 10:
                echo += tls.recv(4096)
            expect(echo == b"ping-frame", echo)

    def concurrent_requests():
        errors = []

        def one(i):
            try:
                status, _, body = h1_get(https_port, "a.test", ca_a, f"/c/{i}")
                if status != 200 or json.loads(body)["headers"][":path"] != \
                        f"/c/{i}":
                    errors.append((status, body[:100]))
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=one, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        expect(not errors, errors[:3])

    # --- Verdicts ------------------------------------------------------------

    chrome_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

    def shadow_verdict_headers():
        out = os.path.join(workdir, "out")
        status, _ = curl(https_port, "a.test", ca_a, "/verdict", out)
        expect(status == 200, status)  # Shadow mode: never blocked.
        h = json.load(open(out))["headers"]
        expect(h["x-bot-class"] == "bot", h)
        expect(int(h["x-bot-score"]) >= 70, h)
        expect("automation_user_agent" in h["x-bot-reasons"], h)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/verdict")
        expect(event["class"] == "bot" and event["action"] == "allow", event)
        expect(event["would_action"] == "block", event)

    def enforce_blocks_spoofed_browser():
        status, _, body = h1_get(
            https_port, "www.a.test", ca_a, "/enforced",
            f"User-Agent: {chrome_ua}\r\nAccept-Language: en\r\n".encode())
        expect(status == 403, (status, body))
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/enforced")
        expect(event["action"] == "block" and event["local"] is True, event)
        expect("ua_tls_mismatch" in event["reasons"], event)
        # Same client on a shadow host passes, tagged.
        status, _, body = h1_get(
            https_port, "a.test", ca_a, "/tagged",
            f"User-Agent: {chrome_ua}\r\n".encode())
        expect(status == 200, status)
        expect(json.loads(body)["headers"]["x-bot-class"] == "bot", body)

    # --- Proxy over HTTP/2 (curl) -------------------------------------------

    def h2_requests():
        out = os.path.join(workdir, "out")
        status, version = curl(https_port, "a.test", ca_a, "/h2/7", out,
                               ["-H", "user-agent: e2e-h2"])
        expect((status, version) == (200, "2"), (status, version))
        seen = json.load(open(out))
        expect(seen["headers"][":path"] == "/h2/7", seen)
        expect(seen["headers"]["x-forwarded-for"] == "127.0.0.1", seen)
        status, _ = curl(https_port, "a.test", ca_a, "/big?bytes=8388608", out)
        expect(status == 200 and os.path.getsize(out) == 8388608,
               os.path.getsize(out))
        upload = os.path.join(workdir, "upload")
        with open(upload, "wb") as f:
            f.write(os.urandom(3 * 1024 * 1024))
        status, _ = curl(https_port, "a.test", ca_a, "/upload", out,
                         ["--data-binary", f"@{upload}"])
        expect(json.load(open(out))["body_len"] == 3 * 1024 * 1024, "upload")
        status, _ = curl(https_port, "a.test", ca_a, "/trailers", out)
        expect(status == 200, status)

    # --- Routing, passthrough, certificates ---------------------------------

    def wildcard_certificate():
        status, _, body = h1_get(https_port, "x.w.test", ca_w, "/")
        expect(status == 200, status)
        expect(json.loads(body)["sni"] == "x.w.test", body)

    def passthrough_unknown_host():
        fields, local_port, _ = line_request(https_port, "b.test", ca_up)
        expect(fields["sni"] == "b.test", fields)
        expect(fields["src"] == f"127.0.0.1:{local_port}", fields)
        expect(fields["authority"] == "b.test", fields)

    def passthrough_acme_tls_alpn():
        fields, _, alpn = line_request(https_port, "a.test", ca_up,
                                       ["acme-tls/1"])
        expect(alpn == "acme-tls/1", f"client ALPN {alpn}")
        expect(fields["alpn"] == "acme-tls/1", fields)

    def passthrough_policy():
        fields, _, _ = line_request(https_port, "grpc.a.test", ca_up)
        expect(fields["sni"] == "grpc.a.test", fields)

    def plain_http_passthrough():
        with socket.create_connection(("127.0.0.1", http_port),
                                      timeout=5) as s:
            local_port = s.getsockname()[1]
            s.sendall(b"/.well-known/acme-challenge/x\n")
            fields = parse_reply(s.recv(4096).decode())
        expect(fields["upstream"] == "plain", fields)
        expect(fields["src"] == f"127.0.0.1:{local_port}", fields)

    def non_tls_rejected():
        with socket.create_connection(("127.0.0.1", https_port),
                                      timeout=5) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
            expect(s.recv(1024) == b"", "expected the connection to close")

    def client_hello_timeout():
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", https_port),
                                      timeout=5) as s:
            expect(s.recv(1024) == b"", "expected the connection to close")
        elapsed = time.monotonic() - started
        expect(0.8 <= elapsed <= 3, f"closed after {elapsed:.2f}s")

    def acme_reload():
        try:
            line_request(https_port, "c.test", ca_c)
            raise AssertionError("c.test was terminated before the reload")
        except ssl.SSLCertVerificationError:
            pass  # Passed through to the upstream certificate.
        write_atomic(acme_path, acme_json([(*gw_a, "a.test"),
                                           (*gw_w, "*.w.test"),
                                           (*gw_c, "c.test")]))
        deadline = time.monotonic() + 5
        while True:
            try:
                status, _, body = h1_get(https_port, "c.test", ca_c, "/")
                expect(json.loads(body)["sni"] == "c.test", body)
                return
            except ssl.SSLCertVerificationError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.1)

    def broken_acme_keeps_certificates():
        with open(acme_path, "w") as f:
            f.write('{"le": {"Certificates": [')
        time.sleep(0.6)
        status, _, _ = h1_get(https_port, "a.test", ca_a, "/")
        expect(status == 200, status)

    # --- Events --------------------------------------------------------------

    def events_http11_request():
        status, _, _ = h1_get(
            https_port, "a.test", ca_a, "/items/42?token=secret",
            b"User-Agent: event-agent\r\nAccept-Language: en-US\r\n")
        expect(status == 200, status)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("user_agent") == "event-agent")
        expect(event["method"] == "GET", event)
        expect(event["status"] == 200 and event["local"] is False, event)
        expect(event["host"] == "a.test", event)
        expect(event["path_group"] == "/items/:n", event)
        expect(event["header_names"] == ["Host", "User-Agent",
                                         "Accept-Language"], event)
        expect(event["ja4"].startswith("t13d"), event)
        expect(event["response_bytes"] > 0, event)
        if sys.platform.startswith("linux"):
            expect(event["tcp_fp"].startswith("4:64:"), event)
            expect(("ja4t" in event) == ja4plus, event)
        expect(("ja4h" in event) == ja4plus, event)
        conn = nats.find("e2e.events.conn",
                         lambda e: e["conn_id"] == event["conn_id"] and
                         e["instance"] == event["instance"])
        expect(conn["route"] == "terminate" and conn["requests"] == 1, conn)
        expect(conn["alpn"] == "http/1.1", conn)

    def events_h2_request():
        out = os.path.join(workdir, "out")
        curl(https_port, "a.test", ca_a, "/h2/9", out,
             ["-H", "user-agent: e2e-h2-event"])
        event = nats.find("e2e.events.req",
                          lambda e: e.get("user_agent") == "e2e-h2-event")
        expect(event["http_version"] == "2", event)
        expect(event["path_group"] == "/h2/:n", event)
        expect(event["status"] == 200, event)
        expect(event["h2_fp"].count("|") == 3, event)
        expect(event["pseudo_order"].startswith("m,"), event)

    def events_local_and_passthrough():
        h1_get(https_port, "noh2.test", ca_a, "/fail")
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/fail")
        expect(event["status"] == 502 and event["local"] is True, event)
        with socket.create_connection(("127.0.0.1", http_port),
                                      timeout=5) as s:
            s.sendall(b"GET /plain HTTP/1.1\r\nHost: a.test\r\n"
                      b"User-Agent: e2e-plain\r\n\r\n")
            s.recv(4096)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("user_agent") == "e2e-plain")
        conn = nats.find("e2e.events.conn",
                         lambda e: e["conn_id"] == event["conn_id"])
        expect(conn["reason"] == "plain_http", conn)
        nats.find("e2e.events.conn",
                  lambda e: e.get("sni") == "b.test" and
                  e["route"] == "passthrough" and "ja4" in e)
        nats.find("e2e.events.conn",
                  lambda e: e["reason"] == "not_tls" and e["route"] == "reject")

    def events_keep_secrets():
        for payload in nats.payloads():
            expect("secret" not in payload, payload)
            expect("127.0.0.1" not in payload, payload)
            expect("6.6.6.6" not in payload, payload)

    def metrics_exposed():
        body = urllib.request.urlopen(metrics_url + "/metrics",
                                      timeout=2).read().decode()
        values = {}
        for line in body.splitlines():
            if line and not line.startswith("#"):
                key, value = line.rsplit(" ", 1)
                values[key] = float(value)
        proxied = values['bot_shield_proxied_requests_total{source="upstream"}']
        expect(proxied >= 60, f"proxied {proxied}")
        opened = values["bot_shield_upstream_connections_opened_total"]
        # Pool reuse: a handful of HTTP/2 connections for ~80 requests.
        expect(1 <= opened <= 12, f"upstream connections {opened}")
        expect(values["bot_shield_websocket_tunnels_total"] >= 1, "websocket")
        expect(values['bot_shield_verdicts_total{class="bot"}'] >= 2, "bots")
        expect(values['bot_shield_blocks_total{mode="enforce"}'] >= 1, "blocks")
        expect(values['bot_shield_blocks_total{mode="shadow"}'] >= 1,
               "shadow blocks")
        expect(values['bot_shield_connections_rejected_total'
                      '{reason="client_hello_timeout"}'] >= 1, "timeout count")
        expect(values["bot_shield_nats_connected"] == 1, "nats connected")
        expect(values['bot_shield_events_total{result="published"}'] >= 50,
               "events published")

    for name, fn in [
        ("h1: GET with forwarding headers over the h2 pool", h1_get_forwarding),
        ("h1: keep-alive and pipelining", h1_keep_alive_and_pipelining),
        ("h1: 3 MB upload and chunked upload", h1_uploads),
        ("h1: 8 MB download, status, trailers", h1_big_download_and_status),
        ("h1: 502 when the upstream fails", bad_gateway_when_upstream_fails),
        ("h1: WebSocket tunnel", websocket_tunnel),
        ("h1: 50 concurrent requests", concurrent_requests),
        ("h2: GET, 8 MB download, 3 MB upload, trailers", h2_requests),
        ("verdict: shadow mode tags, never blocks", shadow_verdict_headers),
        ("verdict: enforce host blocks spoofed browser",
         enforce_blocks_spoofed_browser),
        ("wildcard certificate", wildcard_certificate),
        ("passthrough unknown host with PROXY v2", passthrough_unknown_host),
        ("passthrough acme-tls/1", passthrough_acme_tls_alpn),
        ("passthrough policy host", passthrough_policy),
        ("plain http passthrough", plain_http_passthrough),
        ("non-TLS rejected", non_tls_rejected),
        ("client hello timeout", client_hello_timeout),
        ("acme.json reload", acme_reload),
        ("broken acme.json keeps certificates", broken_acme_keeps_certificates),
        ("events: HTTP/1.1 request with outcome", events_http11_request),
        ("events: HTTP/2 request", events_h2_request),
        ("events: local 502, plain HTTP, passthrough, reject",
         events_local_and_passthrough),
        ("events: no secrets or full IPs", events_keep_secrets),
        ("metrics", metrics_exposed),
    ]:
        checks.run(name, fn)

    def graceful_shutdown():
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        code = process.wait(timeout=10)
        expect(code == 0, f"exit code {code}")
        elapsed = time.monotonic() - started
        expect(elapsed < 5, f"shutdown took {elapsed:.1f}s")

    checks.run("graceful shutdown (pool drained)", graceful_shutdown)
    if process.poll() is None:
        process.kill()
    upstream_process.kill()
    log_file.close()

    if checks.failed:
        print(f"\n{checks.failed} check(s) failed; gateway log:\n")
        print(open(log_path).read()[-4000:])
        sys.exit(1)
    shutil.rmtree(workdir)
    print("\nall e2e checks passed")


if __name__ == "__main__":
    main()
