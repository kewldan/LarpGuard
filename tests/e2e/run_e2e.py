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
import hashlib
import http.client
import http.server
import socketserver
import json
import os
import random
import re
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
import urllib.parse
import urllib.request


def find_openssl():
    for candidate in ("/opt/homebrew/opt/openssl@3/bin/openssl",
                      "/usr/local/opt/openssl@3/bin/openssl", "openssl"):
        path = shutil.which(candidate)
        if path:
            return path
    sys.exit("openssl not found")


# Extra gateways stay off the internet (downloads are tested on the main one).
OFFLINE = """asn: {url: ""}
crawlers: {ip_ranges: false}
"""


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


_issued_ports = set()


def free_port():
    """A port free for TCP and UDP, below the ephemeral ranges (macOS
    49152+, Linux 32768+): a port the kernel handed out with bind(0) could
    be taken by one of the tests' outgoing connections before the gateway
    binds it (about one start in ten)."""
    for _ in range(1000):
        port = random.randint(20000, 32000)
        if port in _issued_ports:
            continue
        try:
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                with socket.socket(socket.AF_INET, kind) as s:
                    s.bind(("127.0.0.1", port))
        except OSError:
            continue
        _issued_ports.add(port)
        return port
    raise RuntimeError("no free port")


def wait_port(port, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not open")


class FakeHttp:
    """HTTP(S) server for the gateway's own outbound requests: siteverify,
    the ASN database, Web Bot Auth key directories."""

    def __init__(self, routes, cert=None):
        self.routes = routes
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def serve(self, body=b""):
                path, _, query = self.path.partition("?")
                outer.requests.append((self.command, self.path, body))
                route = outer.routes.get(path)
                status, kind, data = (route(self.command, query, body)
                                      if route else (404, "text/plain", b""))
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self.serve()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.serve(self.rfile.read(length))

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
                                                      Handler)
        if cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*cert)
            self.server.socket = context.wrap_socket(self.server.socket,
                                                     server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever,
                         daemon=True).start()


def node_ed25519_key():
    """A fresh Ed25519 key as a private JWK (node's crypto)."""
    return json.loads(subprocess.run(
        ["node", "-e", "const k = require('crypto').generateKeyPairSync("
         "'ed25519'); process.stdout.write(JSON.stringify("
         "k.privateKey.export({format: 'jwk'})))"],
        capture_output=True, text=True, check=True, timeout=30).stdout)


def node_sign(jwk, message):
    """Base64 Ed25519 signature of `message` (node's crypto)."""
    script = ("const c = require('crypto'); const k = c.createPrivateKey("
              "{key: JSON.parse(process.argv[1]), format: 'jwk'}); "
              "process.stdout.write(c.sign(null, require('fs').readFileSync(0),"
              " k).toString('base64'))")
    return subprocess.run(["node", "-e", script, json.dumps(jwk)],
                          input=message.encode(), capture_output=True,
                          check=True, timeout=30).stdout.decode()


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


class FakeDocker:
    """Docker Engine API on a unix socket serving /containers/json."""

    def __init__(self, path, containers):
        self.path = path
        self.containers = containers
        docker = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 (http.server API)
                body = json.dumps(docker.containers).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        class Server(socketserver.ThreadingMixIn,
                     socketserver.UnixStreamServer):
            daemon_threads = True

            def get_request(self):
                request, _ = super().get_request()
                return request, ("docker", 0)

        if os.path.exists(path):
            os.remove(path)
        self.server = Server(path, Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def docker_container(name, labels):
    return {"Id": name + "-0123456789", "Names": ["/" + name],
            "Labels": labels, "State": "running"}


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("bot-shield", timeout=5)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(self.unix_path)


def admin_call(path, method, target, body=None):
    connection = UnixHTTPConnection(path)
    payload = json.dumps(body) if body is not None else None
    connection.request(method, target, body=payload,
                       headers={"Content-Type": "application/json"})
    response = connection.getresponse()
    data = json.loads(response.read() or b"null")
    connection.close()
    return response.status, data


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


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_DATA, H2_HEADERS, H2_RST_STREAM, H2_SETTINGS, H2_GOAWAY = 0, 1, 3, 4, 7
H2_END_STREAM, H2_END_HEADERS = 0x1, 0x4


def h2_frame(kind, flags, stream, payload=b""):
    return (struct.pack(">I", len(payload))[1:] + bytes([kind, flags]) +
            struct.pack(">I", stream) + payload)


def h2_request_block(authority, path="/"):
    """HPACK for GET https://<authority><path>, no Huffman, no indexing."""
    return (b"\x82\x87" + b"\x04" + bytes([len(path)]) + path.encode() +
            b"\x01" + bytes([len(authority)]) + authority.encode())


def h2_connect(port, server_name, cafile):
    tls = tls_socket(port, server_name, cafile, ["h2"])
    expect(tls.selected_alpn_protocol() == "h2", "no h2")
    tls.sendall(H2_PREFACE + h2_frame(H2_SETTINGS, 0, 0) +
                h2_frame(H2_SETTINGS, 1, 0))
    return tls


def h2_read_frames(tls, timeout=10):
    """Reads frames until the server closes; [(kind, flags, stream, data)]."""
    tls.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = tls.recv(65536)
        except (ConnectionError, ssl.SSLError):
            break
        if not chunk:
            break
        data += chunk
    frames = []
    while len(data) >= 9:
        length = int.from_bytes(data[:3], "big")
        if len(data) < 9 + length:
            break
        frames.append((data[3], data[4],
                       int.from_bytes(data[5:9], "big") & 0x7fffffff,
                       data[9:9 + length]))
        data = data[9 + length:]
    return frames


def wait_closed(sock, timeout):
    """Seconds until the peer closes `sock` (fails after `timeout`)."""
    started = time.monotonic()
    sock.settimeout(timeout)
    try:
        while sock.recv(4096):
            pass
    except (ConnectionError, ssl.SSLError):
        pass
    except socket.timeout:
        raise AssertionError(f"still open after {timeout}s")
    return time.monotonic() - started


def read_metrics(url):
    body = urllib.request.urlopen(url + "/metrics", timeout=2).read().decode()
    values = {}
    for line in body.splitlines():
        if line and not line.startswith("#"):
            key, value = line.rsplit(" ", 1)
            values[key] = float(value)
    return values


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


def solve_challenge(page, webdriver=False, renderer="Apple M2",
                    user_agent=""):
    """Runs the challenge page's script in node; returns the verify URL.

    Node has no DOM: the sandbox stubs what the probes touch so they see a
    normal desktop browser (or a software renderer, to test escalation).
    Natives are real node functions so the tampering check stays quiet.
    """
    script = page[page.index("<script>") + 8:page.index("</script>")]
    harness = """
const vm = require("vm");
const proto = {webdriver: %s, languages: ["en-US", "en"],
               hardwareConcurrency: 8, platform: "MacIntel",
               userAgent: %s, plugins: {length: 5}, maxTouchPoints: 0,
               userAgentData: {brands: [{brand: "Chromium"}]}};
function Navigator() {}
Navigator.prototype = proto;
const context2d = {
  font: "", fillStyle: "", globalCompositeOperation: "",
  fillRect() {}, fillText() {}, beginPath() {}, arc() {}, fill() {},
  measureText() { return {width: 100 + this.font.length}; },
};
const webgl = {
  VENDOR: 1, RENDERER: 2, MAX_TEXTURE_SIZE: 3, MAX_RENDERBUFFER_SIZE: 4,
  MAX_VERTEX_ATTRIBS: 5, MAX_VARYING_VECTORS: 6,
  getExtension() {
    return {UNMASKED_VENDOR_WEBGL: 1, UNMASKED_RENDERER_WEBGL: 2};
  },
  getParameter(p) { return p === 1 ? "Apple" : p === 2 ? %s : 16384; },
  getSupportedExtensions() { return ["a", "b", "c"]; },
};
function HTMLCanvasElement() {}
HTMLCanvasElement.prototype.toDataURL = Math.max;
const document = {
  createElement() {
    return {getContext(type) { return type === "2d" ? context2d : webgl; },
            toDataURL() { return "data:image/png;base64," + "Q".repeat(300); }};
  },
};
const sandbox = {
  navigator: Object.create(proto), Navigator, HTMLCanvasElement, document,
  screen: {width: 1512, height: 982, availWidth: 1512, availHeight: 950,
           colorDepth: 30},
  devicePixelRatio: 2, outerWidth: 1512, outerHeight: 950, innerWidth: 1512,
  innerHeight: 860,
  location: {replace: (u) => { process.stdout.write(u); process.exit(0); }},
  TextEncoder, btoa, unescape, encodeURIComponent, Date, Intl, setTimeout,
  clearTimeout,
};
sandbox.window = sandbox;
vm.runInNewContext(require("fs").readFileSync(0, "utf8"), sandbox);
// The script finishes asynchronously (Promise, timers); give up after 30 s.
setTimeout(() => process.exit(1), 30000);
""" % ("true" if webdriver else "false", json.dumps(user_agent),
       json.dumps(renderer))
    result = subprocess.run(["node", "-e", harness], input=script,
                            capture_output=True, text=True, timeout=60,
                            check=True)
    if not result.stdout:
        raise AssertionError("challenge script did not finish: " +
                             result.stderr)
    return result.stdout


def solve_pow(nonce, bits):
    counter = 0
    while True:
        digest = hashlib.sha256(f"{nonce}:{counter}".encode()).digest()
        value = int.from_bytes(digest, "big")
        if value >> (256 - bits) == 0:
            return counter
        counter += 1


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def browser_signals(user_agent=""):
    """Signals of an ordinary desktop browser, as the probes report them."""
    return b64url(json.dumps({
        "wd": False, "lang": 2, "ph": False, "brands": ["Chromium"],
        "ua": hashlib.sha256(user_agent.encode()).hexdigest()[:16],
        "cv": "0123456789abcdef", "cvn": 0, "glr": "Apple M2",
        "fn": 12, "pl": 5, "nt": 0, "cdp": 0, "wm": -1,
        "sc": [1512, 982, 1512, 950, 30, 200, 1512, 950, 1512, 860]}).encode())


def page_nonce(page):
    start = page.index('N="') + 3
    return page[start:page.index('"', start)]


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
                          "noh2.test", "x.w.test", "y.w.test", "www.a.test"])
    acme_path = os.path.join(workdir, "acme.json")
    write_atomic(acme_path, acme_json([(*gw_a, "a.test"), (*gw_w, "*.w.test")]))

    tls_port, plain_port = free_port(), free_port()
    upstream_process = subprocess.Popen(
        [fake, str(tls_port), str(plain_port), *upstream])
    wait_port(tls_port)
    nats = FakeNats()
    docker = FakeDocker(
        os.path.join(tempfile.gettempdir(), f"bs-docker-{os.getpid()}.sock"),
        [docker_container("labelled", {
            "traefik.http.routers.labelled.rule": "Host(`x.w.test`)",
            "botshield.mode": "enforce",
            "botshield.ratelimit.burst": "rate=2/m path=/labels/limited*",
            "botshield.challenge.paths": "/labels/checkout*",
            "botshield.honeypot.paths": "/labels/trap",
            "botshield.ai_crawlers": "allow"}),
         docker_container("passthru", {"botshield.hosts": "y.w.test",
                                       "botshield.passthrough": "true"}),
         docker_container("override", {"botshield.hosts": "www.a.test",
                                       "botshield.mode": "shadow"}),
         docker_container("offhost", {"botshield.hosts": "z.w.test",
                                      "botshield.mode": "off"}),
         docker_container("unrelated", {"traefik.enable": "true"})])

    https_port, http_port, metrics_port = free_port(), free_port(), free_port()
    admin_socket = os.path.join(tempfile.gettempdir(),
                                f"bs-admin-{os.getpid()}.sock")
    lists_file = os.path.join(workdir, "lists.json")
    modes_file = os.path.join(workdir, "modes.json")
    attack_file = os.path.join(workdir, "attack.json")
    settings_file = os.path.join(workdir, "settings.yaml")
    config_path = os.path.join(workdir, "bot-shield.yaml")
    keys_path = os.path.join(workdir, "keys.json")
    model_path = os.path.join(workdir, "model.json")
    fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                           "data", "gbdt_fixture.json")
    with open(fixture) as f, open(model_path, "w") as out:
        json.dump(json.load(f)["model"], out)
    with open(keys_path, "w") as f:
        json.dump({"active": "k1", "keys": {
            "k1": base64.b64encode(os.urandom(32)).decode()}}, f)
    # CAPTCHA provider: tokens "ok:<cdata>:<n>" pass, anything else fails.
    captcha_secret = os.path.join(workdir, "turnstile.secret")
    with open(captcha_secret, "w") as f:
        f.write("e2e-secret\n")

    def siteverify(method, query, body):
        form = urllib.parse.parse_qs(body.decode())
        token = form.get("response", [""])[0]
        if (method == "POST" and form.get("secret") == ["e2e-secret"] and
                token.startswith("ok:")):
            reply = {"success": True, "hostname": "www.a.test",
                     "cdata": token.split(":")[1]}
        else:
            reply = {"success": False,
                     "error-codes": ["invalid-input-response"]}
        return 200, "application/json", json.dumps(reply).encode()

    def ip2asn(method, query, body):
        return 200, "text/tab-separated-values", (
            b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"
            b"127.0.0.0\t127.255.255.255\t64500\tZZ\tE2E-ISP Example\n")

    outbound = FakeHttp({"/siteverify": siteverify, "/ip2asn.tsv": ip2asn})
    # Web Bot Auth agent: key directory over HTTPS on "localhost".
    agent_cert = make_cert(workdir, "agent", ["localhost"])
    agent_key = node_ed25519_key()
    agent_directory = json.dumps({"keys": [{
        "kty": "OKP", "crv": "Ed25519", "x": agent_key["x"]}]}).encode()
    agent = FakeHttp({
        "/.well-known/http-message-signatures-directory":
            lambda method, query, body: (
                200, "application/http-message-signatures-directory+json",
                agent_directory)}, cert=agent_cert)

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
rules:
  - name: monitoring
    when: 'header("x-monitor") == "e2e-token"'
    action: allow
  - name: admin
    when: 'path ~ "/admin*"'
    action: block
  - name: guarded
    when: 'path ~ "/guarded*"'
    action: challenge
  - name: slow
    when: 'path ~ "/tarpit*"'
    action: tarpit
  - name: fake
    when: 'path ~ "/decoy*"'
    action: decoy
  - name: slowdown
    when: 'path ~ "/throttled*"'
    action: throttle
  - name: human-check
    when: 'path ~ "/captcha*"'
    action: captcha
  # The fake origin's /status/NNN checks a limit and /qc a rule, not the
  # verdict: the bare requests would otherwise be scored a bot (more so on
  # Linux, with TCP signals). A score rule, unlike allow, leaves rate limits
  # and block rules in force.
  - name: status-paths
    when: 'path ~ "/status/*" or path ~ "/qc*"'
    action: score
    score: -100
  - name: query-and-cookie
    when: 'path ~ "/qc*" and query("mode") == "x" and not has_cookie("pass")'
    action: block
  - name: asn-rule
    when: 'asn == 64500 and path ~ "/asn-block*"'
    action: block
rate_limits:
  - name: limited-path
    paths: ["/limited*"]
    key: [ip, host]
    rate: 3/m
  - name: api-keys
    paths: ["/api/*"]
    key: ["header:x-api-key"]
    rate: 2/m
  - name: failed-logins
    hosts: [www.a.test]
    paths: ["/status/*"]
    key: [ip, host]
    statuses: [401]
    rate: 2/m
timeouts:
  client_hello: 1s
events:
  nats: nats://127.0.0.1:{nats.port}
  subject_prefix: e2e.events
  ip_salt: e2e-salt
docker:
  socket: {docker.path}
  poll_interval: 200ms
crawlers:
  ai: block
  ai_robots: true
  ip_ranges: false
decoy:
  labyrinth: true
asn:
  url: http://127.0.0.1:{outbound.port}/ip2asn.tsv
web_bot_auth:
  trusted: ["localhost"]
ca_file: {agent_cert[0]}
captcha:
  provider: turnstile
  site_key: e2e-site-key
  secret_file: {captcha_secret}
  verify_url: http://127.0.0.1:{outbound.port}/siteverify
  difficulty: 4
honeypot:
  paths: ["/.env", "/trap/*"]
  ttl: 1s
http3:
  enabled: true
model:
  file: {model_path}
  threshold: 0.99
throttle:
  rate: 2/m
  key: [ip]
tarpit:
  duration: 1s
  interval: 200ms
  chunk: 4
challenge:
  keys_file: {keys_path}
  token_ttl: 10m
  difficulty: {{suspicious: 8, bot: 10}}
admin:
  socket: {admin_socket}
  state_file: {lists_file}
  modes_file: {modes_file}
  attack_file: {attack_file}
  settings_file: {settings_file}
  decisions: 1000
metrics:
  listen: 127.0.0.1:{metrics_port}
log_level: debug
whoami: true
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

    def rules_override_verdicts():
        # Allow rule beats the class block on an enforce host.
        status, _, body = h1_get(
            https_port, "www.a.test", ca_a, "/monitored",
            f"User-Agent: {chrome_ua}\r\nX-Monitor: e2e-token\r\n".encode())
        expect(status == 200, (status, body))
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/monitored")
        expect("rule:monitoring" in event["reasons"], event)
        expect(event["class"] == "bot" and event["action"] == "allow", event)
        # Block rule: only tagged in shadow mode, enforced on www.a.test.
        status, _, _ = h1_get(https_port, "a.test", ca_a, "/admin/panel")
        expect(status == 200, status)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/admin/panel")
        expect(event["would_action"] == "block", event)
        expect("rule:admin" in event["reasons"], event)
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/admin/panel")
        expect(status == 403, status)

    def js_challenge():
        html = b"Accept: text/html\r\n"
        status, headers, body = h1_get(https_port, "www.a.test", ca_a,
                                       "/guarded/page?x=1", html)
        expect(status == 403 and headers["content-type"].startswith(
            "text/html"), (status, headers))
        expect(headers.get("cache-control") == "no-store", headers)
        verify = solve_challenge(body.decode())
        expect(verify.startswith("/__bs/verify?n="), verify)
        status, headers, _ = h1_get(https_port, "www.a.test", ca_a, verify)
        expect(status == 302, status)
        expect(headers["location"] == "/guarded/page?x=1", headers)
        cookie = headers["set-cookie"].split(";")[0]
        expect(cookie.startswith("__bs=v1."), cookie)
        # With the token: through to the upstream, without our cookie.
        status, _, body = h1_get(
            https_port, "www.a.test", ca_a, "/guarded/page?x=1",
            html + f"Cookie: app=1; {cookie}\r\n".encode())
        expect(status == 200, (status, body))
        seen = json.loads(body)["headers"]
        expect(seen.get("cookie") == "app=1", seen)
        expect("token_valid" in seen["x-bot-reasons"], seen)
        status, _, body = h1_get(https_port, "www.a.test", ca_a,
                                 "/guarded/only", f"Cookie: {cookie}\r\n"
                                 .encode())
        expect(status == 200 and "cookie" not in json.loads(body)["headers"],
               body)
        # A forged token does not count.
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/guarded/page",
                              html + f"Cookie: {cookie}0\r\n".encode())
        expect(status == 403, status)
        # Non-navigation requests get JSON with the challenge URL.
        status, headers, body = h1_get(https_port, "www.a.test", ca_a,
                                       "/guarded/api",
                                       b"Accept: application/json\r\n")
        expect(status == 403 and headers["content-type"] == "application/json",
               (status, headers))
        expect(json.loads(body) == {
            "error": "challenge_required",
            "challenge": "/__bs/challenge?r=%2Fguarded%2Fapi"}, body)
        # The challenge page by URL, and a failing (webdriver) solution.
        status, _, body = h1_get(https_port, "www.a.test", ca_a,
                                 "/__bs/challenge?r=%2Fguarded%2Fapi")
        expect(status == 200, status)
        verify = solve_challenge(body.decode(), webdriver=True)
        status, headers, _ = h1_get(https_port, "www.a.test", ca_a, verify)
        expect(status == 403 and "set-cookie" not in headers, status)
        event = nats.find("e2e.events.req", lambda e: "challenge:failed:"
                          "webdriver" in e.get("reasons", []))
        expect(event["local"] is True, event)
        # Shadow host: only recorded.
        status, _, _ = h1_get(https_port, "a.test", ca_a, "/guarded/shadow",
                              html)
        expect(status == 200, status)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/guarded/shadow")
        expect(event["would_action"] == "challenge", event)

    def challenge_escalation():
        # A software renderer is soft: the CAPTCHA decides, not a token.
        html = b"Accept: text/html\r\n"
        _, _, body = h1_get(https_port, "www.a.test", ca_a, "/guarded/soft",
                            html)
        verify = solve_challenge(body.decode(), renderer="Google SwiftShader")
        status, headers, body = h1_get(https_port, "www.a.test", ca_a, verify)
        expect(status == 403 and "set-cookie" not in headers, status)
        expect(b"cf-turnstile" in body and b"e2e-site-key" in body, body[:300])
        event = nats.find("e2e.events.req", lambda e: (
            "challenge:escalated:software_renderer" in e.get("reasons", [])))
        expect(len(event.get("client_fp", "")) == 16, event)

    def captcha_turnstile():
        html = b"Accept: text/html\r\n"
        status, headers, body = h1_get(https_port, "www.a.test", ca_a,
                                       "/captcha-gate?x=1", html)
        expect(status == 403 and b"cf-turnstile" in body, (status, body[:200]))
        status, _, api = h1_get(https_port, "www.a.test", ca_a,
                                "/captcha-api", b"Accept: application/json\r\n")
        expect(status == 403 and json.loads(api) == {
            "error": "captcha_required",
            "captcha": "/__bs/captcha?r=%2Fcaptcha-api"}, api)

        def verify_url(page, token, user_agent=""):
            nonce = page_nonce(page)
            cdata = hashlib.sha256(nonce.encode()).hexdigest()[:32]
            return ("/__bs/captcha/verify?n=" + urllib.parse.quote(nonce) +
                    f"&c={solve_pow(nonce, 4)}&t=" +
                    urllib.parse.quote(token.replace("CDATA", cdata)) +
                    "&s=" + browser_signals(user_agent))

        # HTTP/1.1: the provider is asked in the background, the answer
        # follows on the same connection.
        status, headers, _ = h1_get(https_port, "www.a.test", ca_a,
                                    verify_url(body.decode(), "ok:CDATA:1"))
        expect(status == 302, (status, headers))
        expect(headers["location"] == "/captcha-gate?x=1", headers)
        cookie = headers["set-cookie"].split(";")[0]
        expect(cookie.startswith("__bs=v2."), cookie)
        status, _, body = h1_get(https_port, "www.a.test", ca_a,
                                 "/captcha-gate?x=1",
                                 html + f"Cookie: {cookie}\r\n".encode())
        expect(status == 200, status)
        expect("token_valid" in json.loads(body)["headers"]["x-bot-reasons"],
               body)
        # The provider says no.
        _, _, body = h1_get(https_port, "www.a.test", ca_a, "/captcha-gate",
                            html)
        status, headers, _ = h1_get(https_port, "www.a.test", ca_a,
                                    verify_url(body.decode(), "forged"))
        expect(status == 403 and "set-cookie" not in headers, status)
        nats.find("e2e.events.req", lambda e: (
            "captcha:failed:provider:invalid-input-response" in
            e.get("reasons", [])))
        posts = [r for r in outbound.requests if r[1] == "/siteverify"]
        expect(b"remoteip=127.0.0.1" in posts[0][2], posts[0])

        # HTTP/2 (curl): the same deferred answer on a stream.
        page_path = os.path.join(workdir, "captcha-page.html")
        status, _ = curl(https_port, "www.a.test", ca_a, "/captcha-gate",
                         page_path, ("-A", "e2e-curl", "-H",
                                     "Accept: text/html"))
        expect(status == 403, status)
        with open(page_path) as f:
            page = f.read()
        header_path = os.path.join(workdir, "captcha-headers.txt")
        status, version = curl(https_port, "www.a.test", ca_a,
                               verify_url(page, "ok:CDATA:2", "e2e-curl"),
                               os.devnull, ("-A", "e2e-curl", "-D",
                                            header_path))
        expect(status == 302 and version == "2", (status, version))
        with open(header_path) as f:
            expect("__bs=v2." in f.read(), "h2 cookie")

    def asn_database():
        for _ in range(100):
            values = read_metrics(metrics_url)
            if values.get("bot_shield_asn_ranges", 0) >= 2:
                break
            time.sleep(0.05)
        expect(values.get("bot_shield_asn_ranges") == 2, values.get(
            "bot_shield_asn_ranges"))
        # New connections get their AS: rules, limits and events see it.
        status, _, _ = h1_get(https_port, "a.test", ca_a, "/asn-block/1",
                              b"User-Agent: e2e-asn\r\n")
        expect(status == 200, status)  # a.test is a shadow host.
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/asn-block/:n")
        expect(event.get("asn") == 64500, event)
        expect("rule:asn-rule" in event["reasons"], event)
        expect(event["would_action"] == "block", event)
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/asn-block/2")
        expect(status == 403, status)

    def web_bot_auth():
        thumbprint = b64url(hashlib.sha256(json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": agent_key["x"]},
            separators=(",", ":")).encode()).digest())
        agent_url = f"https://localhost:{agent.port}"

        def signed(path, tamper=False):
            created = int(time.time())
            params = (f'("@authority" "signature-agent";key="agent1")'
                      f';created={created};keyid="{thumbprint}"'
                      f';alg="ed25519";expires={created + 300}'
                      f';tag="web-bot-auth"')
            base = (f'"@authority": www.a.test\n'
                    f'"signature-agent";key="agent1": "{agent_url}"\n'
                    f'"@signature-params": {params}')
            signature = node_sign(agent_key, base + ("x" if tamper else ""))
            return h1_get(https_port, "www.a.test", ca_a, path, (
                f'Signature-Agent: agent1="{agent_url}"\r\n'
                f"Signature-Input: sig1={params}\r\n"
                f"Signature: sig1=:{signature}:\r\n").encode())

        # The first request fetches the key directory in the background.
        seen = {}
        for _ in range(100):
            status, _, body = signed("/items/7")
            seen = json.loads(body)["headers"] if status == 200 else {}
            if seen.get("x-bot-class") == "verified_bot":
                break
            time.sleep(0.05)
        expect(seen["x-bot-class"] == "verified_bot", seen)
        expect(seen["x-bot-reasons"] == "verified_agent:localhost", seen)
        event = nats.find("e2e.events.req", lambda e: e.get(
            "signed_agent") == "localhost")
        expect(event["class"] == "verified_bot", event)
        # A signature over other bytes is worse than none.
        signed("/items/8", tamper=True)
        nats.find("e2e.events.req", lambda e: (
            "web_bot_auth_invalid" in e.get("reasons", []) and
            e.get("path_group") == "/items/:n"))
        fetched = [r for r in agent.requests if r[1].startswith("/.well-known")]
        expect(len(fetched) == 1, fetched)

    def crawlers():
        gptbot = ("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; "
                  "compatible; GPTBot/1.2; +https://openai.com/gptbot)")
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/ai/enforced",
                              f"User-Agent: {gptbot}\r\n".encode())
        expect(status == 403, status)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/ai/enforced")
        expect("ai_crawler:openai" in event["reasons"], event)
        # crawlers.ai_robots: robots.txt says Disallow for AI crawlers (even
        # with ai: block), and the site's own for everyone else.
        status, _, body = h1_get(https_port, "www.a.test", ca_a, "/robots.txt",
                                 f"User-Agent: {gptbot}\r\n".encode())
        expect(status == 200 and b"Disallow: /\n" in body, (status, body))
        status, _, body = h1_get(https_port, "www.a.test", ca_a, "/robots.txt")
        expect(b"Disallow" not in body, body)
        status, _, body = h1_get(https_port, "a.test", ca_a, "/ai/shadow",
                                 f"User-Agent: {gptbot}\r\n".encode())
        expect(status == 200, status)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/ai/shadow")
        expect(event["would_action"] == "block", event)
        # "Googlebot" from 127.0.0.1: unverified at first, then the reverse
        # DNS check (localhost) fails and it is a fake.
        googlebot = ("Mozilla/5.0 (compatible; Googlebot/2.1; "
                     "+http://www.google.com/bot.html)")
        reasons = []
        for _ in range(60):
            _, _, body = h1_get(https_port, "a.test", ca_a, "/crawler",
                                f"User-Agent: {googlebot}\r\n".encode())
            reasons = json.loads(body)["headers"]["x-bot-reasons"].split(",")
            if "fake_crawler:google" in reasons:
                break
            expect("unverified_crawler" in reasons, reasons)
            time.sleep(0.05)
        expect("fake_crawler:google" in reasons, reasons)
        # Each step of the check is in the event: no published ranges
        # offline, the PTR lookup of 127.0.0.1 fails, so a fake.
        event = nats.find(
            "e2e.events.req",
            lambda e: e.get("path_group") == "/crawler" and
            "result:fake" in e.get("crawler_check", []))
        expect(event["crawler_check"][0] == "claim:google", event)
        expect(any(step.startswith("rdns:") and step != "rdns:queued"
                   for step in event["crawler_check"]), event)
        expect(event.get("alpn") == "http/1.1", event)

    def honeypot_and_behavior():
        # The trap itself, then the same client elsewhere (marked for 1s,
        # so the checks after this one are not affected).
        _, _, body = h1_get(https_port, "a.test", ca_a, "/trap/x")
        reasons = json.loads(body)["headers"]["x-bot-reasons"].split(",")
        expect("honeypot" in reasons, reasons)
        _, _, body = h1_get(https_port, "a.test", ca_a, "/after-trap")
        reasons = json.loads(body)["headers"]["x-bot-reasons"].split(",")
        expect("honeypot_client" in reasons, reasons)
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/.env")
        expect(status == 403, status)
        time.sleep(1.2)
        _, _, body = h1_get(https_port, "a.test", ca_a, "/after-ttl")
        reasons = json.loads(body)["headers"]["x-bot-reasons"]
        expect("honeypot" not in reasons, reasons)
        # Walking through IDs one by one.
        for item in range(1, 13):
            _, _, body = h1_get(https_port, "a.test", ca_a, f"/items/{item}")
        reasons = json.loads(body)["headers"]["x-bot-reasons"].split(",")
        expect("behavior_sequential_ids" in reasons, reasons)
        h1_get(https_port, "a.test", ca_a, "/reset/1")  # Another pattern.

    def tarpit_and_decoy():
        started = time.monotonic()
        status, headers, body = h1_get(https_port, "www.a.test", ca_a,
                                       "/tarpit/x")
        elapsed = time.monotonic() - started
        expect(status == 200 and body == b" " * 20, (status, body))
        expect(0.8 <= elapsed < 3, f"tarpit took {elapsed:.2f}s")
        # HTTP/2 as well.
        out = os.path.join(workdir, "tarpit-h2")
        started = time.monotonic()
        status, version = curl(https_port, "www.a.test", ca_a, "/tarpit/h2",
                               out)
        expect(status == 200 and version == "2", (status, version))
        expect(time.monotonic() - started >= 0.8, "h2 tarpit too fast")
        # A client that leaves frees its slot.
        with tls_socket(https_port, "www.a.test", ca_a, ["http/1.1"]) as tls:
            tls.sendall(b"GET /tarpit/gone HTTP/1.1\r\nHost: www.a.test\r\n\r\n")
            tls.recv(100)
        # Shadow host: only recorded.
        status, _, _ = h1_get(https_port, "a.test", ca_a, "/tarpit/shadow")
        expect(status == 200, status)

        status, headers, body = h1_get(https_port, "www.a.test", ca_a,
                                       "/decoy/list",
                                       b"Accept: text/html\r\n")
        expect(status == 200 and headers["content-type"].startswith(
            "text/html"), (status, headers))
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/decoy/list")
        mark = event["watermark"]
        expect(len(mark) == 12 and mark.encode() in body, (mark, body))
        expect(event["action"] == "decoy" and event["local"] is True, event)
        # decoy.labyrinth: a maze page, the same for the same path, with
        # links deeper in and no indexing.
        expect(b'content="noindex,nofollow"' in body, body)
        links = [m for m in body.split(b'href="')[1:]]
        expect(len(links) == 12 and all(l.startswith(b"/") for l in links),
               body)
        _, _, again = h1_get(https_port, "www.a.test", ca_a, "/decoy/list",
                             b"Accept: text/html\r\n")
        # Each answer has its own watermark; the rest is the same page.
        unmark = lambda page: re.sub(rb"[0-9a-f]{12}", b"", page)
        expect(unmark(again) == unmark(body), (again, body))
        status, headers, body = h1_get(https_port, "www.a.test", ca_a,
                                       "/decoy/api",
                                       b"Accept: application/json\r\n")
        expect(headers["content-type"] == "application/json", headers)
        expect(len(json.loads(body)["items"]) == 2, body)

    def throttle():
        statuses = [h1_get(https_port, "www.a.test", ca_a, "/throttled")[0]
                    for _ in range(3)]
        expect(statuses == [200, 200, 429], statuses)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("rate_limit") == "throttle")
        expect(event["action"] == "rate_limit", event)
        # Shadow host: recorded, not refused.
        statuses = [h1_get(https_port, "a.test", ca_a, "/throttled")[0]
                    for _ in range(3)]
        expect(statuses == [200, 200, 200], statuses)

    def hot_reload():
        original = open(config_path).read()
        reloaded_rule = (
            "  - name: reloaded\n"
            "    when: 'path ~ \"/reloaded*\"'\n"
            "    action: block\n")
        expect(h1_get(https_port, "www.a.test", ca_a, "/reloaded")[0] == 200,
               "before")
        with open(config_path, "w") as f:
            f.write(original.replace("rules:\n", "rules:\n" + reloaded_rule))
        process.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 5
        while h1_get(https_port, "www.a.test", ca_a, "/reloaded")[0] != 403:
            expect(time.monotonic() < deadline, "SIGHUP reload not applied")
            time.sleep(0.05)
        # A broken file is refused and the current rules stay.
        with open(config_path, "w") as f:
            f.write(original.replace("rules:\n", "rules:\n" + reloaded_rule
                                     .replace("path ~", "nonsense ~")))
        status, body = admin_call(admin_socket, "POST", "/reload")
        expect(status == 422 and "nonsense" in body["error"], body)
        expect(h1_get(https_port, "www.a.test", ca_a, "/reloaded")[0] == 403,
               "kept")
        # Back to the original through the admin API.
        with open(config_path, "w") as f:
            f.write(original)
        status, body = admin_call(admin_socket, "POST", "/reload")
        expect(status == 200 and "generation" in body["summary"], body)
        expect(h1_get(https_port, "www.a.test", ca_a, "/reloaded")[0] == 200,
               "after")
        status, body = admin_call(admin_socket, "GET", "/status")
        expect(body["verdicts_generation"] >= 3, body)

    def whoami():
        # curl on a shadow host: text, passes now, blocked in enforce.
        out = os.path.join(workdir, "whoami.txt")
        status, _ = curl(https_port, "a.test", ca_a, "/__bs/whoami", out)
        text = open(out).read()
        expect(status == 200, (status, text))
        expect("You look like curl, an HTTP tool or library." in text, text)
        expect("in enforce mode, blocked." in text, text)
        expect("automation_user_agent" in text, text)
        # A spoofed Chrome on the enforce host is answered, not blocked.
        status, headers, body = h1_get(
            https_port, "www.a.test", ca_a, "/__bs/whoami?format=json",
            f"User-Agent: {chrome_ua}\r\n".encode())
        expect(status == 200, (status, body))
        report = json.loads(body)
        expect(report["you_look_like"].startswith(
            "something that claims to be Chrome"), report)
        expect(report["mode"] == "enforce", report)
        expect(report["verdict"]["action"] == "block", report)
        weights = {r["reason"]: r["weight"]
                   for r in report["verdict"]["reasons"]}
        expect(weights.get("ua_tls_mismatch", 0) > 0, weights)
        expect(report["network"]["ip"] == "127.0.0.1", report)
        expect(report["stack"]["handshake_us"] > 0, report)
        expect(report["stack"]["relayed"] is False, report)
        # A browser's Accept gets the page.
        status, headers, body = h1_get(
            https_port, "a.test", ca_a, "/__bs/whoami",
            b"Accept: text/html,application/xhtml+xml\r\n")
        expect(status == 200 and b"<h1>You look like" in body, body[:200])
        event = nats.find("e2e.events.req",
                          lambda e: "whoami" in e.get("reasons", []) and
                          e.get("host") == "www.a.test")
        expect(event["action"] == "allow" and event["local"] is True, event)
        expect(event["would_action"] == "block", event)
        # Off again (reload): an unknown /__bs/ path.
        original = open(config_path).read()
        with open(config_path, "w") as f:
            f.write(original.replace("whoami: true", "whoami: false"))
        status, body = admin_call(admin_socket, "POST", "/reload")
        expect(status == 200, body)
        status, _, _ = h1_get(https_port, "a.test", ca_a, "/__bs/whoami")
        expect(status == 404, status)
        with open(config_path, "w") as f:
            f.write(original)
        status, body = admin_call(admin_socket, "POST", "/reload")
        expect(status == 200, body)

    def rules_on_query_and_cookies():
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/qc?mode=x")
        expect(status == 403, status)
        for path, extra in [("/qc?mode=y", b""), ("/qc?modex=x", b""),
                            ("/qc?mode=x", b"Cookie: a=1; pass=\r\n")]:
            status, _, _ = h1_get(https_port, "www.a.test", ca_a, path, extra)
            expect(status == 200, (path, extra, status))

    def rate_limits_on_responses():
        def get(path, expected):
            status, headers, _ = h1_get(https_port, "www.a.test", ca_a, path)
            if status != expected:
                # Which verdict answered instead (reasons, action).
                event = nats.find("e2e.events.req", lambda e: (
                    e.get("path_group", "").startswith("/status") and
                    e.get("status") == status), timeout=1)
                raise AssertionError((status, event))
            return headers

        # Successful answers never use the limit up.
        for _ in range(5):
            get("/status/200", 200)
        # Two failures from the origin do; then any request is refused
        # before it reaches the origin.
        for _ in range(2):
            get("/status/401", 401)
        headers = get("/status/200", 429)
        expect(headers["ratelimit-policy"] == '"failed-logins";q=2;w=60',
               headers)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("rate_limit") == "failed-logins")
        expect(event["local"] and event["status"] == 429, event)

    def rate_limits():
        statuses = [h1_get(https_port, "www.a.test", ca_a, "/limited")
                    for _ in range(4)]
        expect([s for s, _, _ in statuses] == [200, 200, 200, 429],
               [s for s, _, _ in statuses])
        _, headers, _ = statuses[3]
        expect(int(headers["retry-after"]) >= 1, headers)
        expect(headers["ratelimit-policy"] == '"limited-path";q=3;w=60',
               headers)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/limited" and
                          e.get("status") == 429)
        expect(event["action"] == "rate_limit" and event["local"], event)
        expect(event["rate_limit"] == "limited-path", event)
        # The monitoring allow rule bypasses the limit.
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/limited",
                              b"X-Monitor: e2e-token\r\n")
        expect(status == 200, status)
        # Shadow host: never refused, only recorded.
        for _ in range(5):
            status, _, _ = h1_get(https_port, "a.test", ca_a, "/limited-shadow")
            expect(status == 200, status)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/limited-shadow" and
                          e.get("would_action") == "rate_limit")
        expect(event["action"] == "allow", event)
        # Per API key; requests without a key are not limited.
        for key, expected in [(b"k1", 200), (b"k1", 200), (b"k1", 429),
                              (b"k2", 200)]:
            status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/api/x",
                                  b"X-Api-Key: " + key + b"\r\n")
            expect(status == expected, (key, status, expected))
        for _ in range(4):
            status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/api/x")
            expect(status == 200, status)

    def docker_labels():
        # botshield.mode=enforce from labels.
        status, _, _ = h1_get(https_port, "x.w.test", ca_w, "/labels",
                              f"User-Agent: {chrome_ua}\r\n".encode())
        expect(status == 403, status)
        # botshield.ratelimit.* scoped to the container's hosts.
        statuses = [h1_get(https_port, "x.w.test", ca_w, "/labels/limited")[0]
                    for _ in range(3)]
        expect(statuses == [200, 200, 429], statuses)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("rate_limit") == "labelled/burst")
        expect(event["status"] == 429, event)
        # botshield.passthrough=true: TLS goes to Traefik untouched.
        fields, _, _ = line_request(https_port, "y.w.test", ca_up)
        expect(fields["sni"] == "y.w.test", fields)
        # botshield.mode=off: plain proxying, no verdict headers.
        out = os.path.join(workdir, "out")
        status, _ = curl(https_port, "z.w.test", ca_w, "/off", out)
        expect(status == 200, status)
        expect("x-bot-score" not in json.load(open(out))["headers"], "off")
        # YAML policy.hosts beats the label (www.a.test stays enforced).
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/yaml-wins",
                              f"User-Agent: {chrome_ua}\r\n".encode())
        expect(status == 403, status)
        # botshield.challenge.paths: a challenge page there (enforced).
        status, headers, _ = h1_get(https_port, "x.w.test", ca_w,
                                    "/labels/checkout/1",
                                    b"Accept: text/html\r\n")
        expect(status == 403 and headers["content-type"].startswith(
            "text/html"), (status, headers))
        event = nats.find("e2e.events.req", lambda e: e.get("path_group")
                          == "/labels/checkout/:n")
        expect("label:challenge_path" in event["reasons"], event)
        # botshield.ai_crawlers=allow beats crawlers.ai: block.
        gptbot = "Mozilla/5.0 (compatible; GPTBot/1.2)"
        status, _, _ = h1_get(https_port, "x.w.test", ca_w, "/labels/ai",
                              f"User-Agent: {gptbot}\r\n".encode())
        expect(status == 200, status)
        # Label changes apply without a restart.
        docker.containers[0]["Labels"]["botshield.mode"] = "shadow"
        deadline = time.monotonic() + 5
        while True:
            status, _, _ = h1_get(https_port, "x.w.test", ca_w, "/relabelled",
                                  f"User-Agent: {chrome_ua}\r\n".encode())
            if status == 200:
                break
            expect(time.monotonic() < deadline, "label change not applied")
            time.sleep(0.1)
        # botshield.honeypot.paths: a trap on these hosts only.
        _, _, body = h1_get(https_port, "x.w.test", ca_w, "/labels/trap")
        reasons = json.loads(body)["headers"]["x-bot-reasons"].split(",")
        expect("honeypot" in reasons, reasons)
        _, _, body = h1_get(https_port, "a.test", ca_a, "/labels/trap")
        reasons = json.loads(body)["headers"]["x-bot-reasons"].split(",")
        expect("honeypot" not in reasons, reasons)
        time.sleep(1.2)  # honeypot.ttl: the mark is gone for later checks.

    def admin_api():
        expect(os.stat(admin_socket).st_mode & 0o777 == 0o600, "socket mode")
        status, body = admin_call(admin_socket, "GET", "/status")
        expect(status == 200 and body["version"], body)
        status, body = admin_call(admin_socket, "GET", "/policy?host=www.a.test")
        expect(body["mode"] == "enforce", body)
        expect(body["mode_source"] == "policy.hosts", body)
        expect(body["route"] == "terminate", body)

        # Block list: a request that is normally let through gets 403.
        status, entry = admin_call(admin_socket, "POST", "/lists", {
            "kind": "ip", "value": "127.0.0.1", "action": "block",
            "host": "www.a.test", "ttl": "5m", "comment": "e2e"})
        expect(status == 201, entry)
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/listed")
        expect(status == 403, status)
        _, body = admin_call(admin_socket, "GET",
                             "/decisions?host=www.a.test&limit=20")
        record = next(d for d in body["decisions"]
                      if d["path_group"] == "/listed")
        expect(f"list:{entry['id']}" in record["reasons"], record)
        expect(record["action"] == "block" and record["ip"] == "127.0.0.1",
               record)
        saved = json.load(open(lists_file))
        expect([e["id"] for e in saved] == [entry["id"]], saved)
        status, _ = admin_call(admin_socket, "DELETE", f"/lists/{entry['id']}")
        expect(status == 200, status)
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/listed")
        expect(status == 200, status)

        # Allow list beats a bot verdict on an enforced host.
        _, entry = admin_call(admin_socket, "POST", "/lists", {
            "kind": "ip", "value": "127.0.0.0/8", "action": "allow",
            "host": "www.a.test"})
        status, _, body = h1_get(https_port, "www.a.test", ca_a, "/allowed",
                                 f"User-Agent: {chrome_ua}\r\n".encode())
        expect(status == 200, status)
        admin_call(admin_socket, "DELETE", f"/lists/{entry['id']}")

        # The request id Traefik sees leads to the decision.
        request_id = json.loads(body)["headers"]["x-bot-request-id"]
        status, record = admin_call(admin_socket, "GET",
                                    f"/decisions/{request_id}")
        expect(status == 200 and record["path_group"] == "/allowed", record)
        expect(record["class"] == "bot" and record["action"] == "allow",
               record)
        event = nats.find("e2e.events.req",
                          lambda e: e.get("request_id") == request_id)
        expect(event["path_group"] == "/allowed", event)
        # Decisions carry the event's prefix and hash, so a consumer that
        # drops the full address can still join them.
        expect(record["ip_prefix"] == event["ip_prefix"] == "127.0.0.0/24",
               (record, event))
        expect(record["ip_hash"] == event["ip_hash"], (record, event))

        # Console host mode: beats policy.hosts at once, survives in its
        # file, and removing it brings the configured mode back.
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/admin/panel")
        expect(status == 403, status)
        status, body = admin_call(admin_socket, "POST", "/policy",
                                  {"host": "www.a.test", "mode": "shadow"})
        expect(status == 200, body)
        _, body = admin_call(admin_socket, "GET", "/policy?host=www.a.test")
        expect(body["mode"] == "shadow" and body["mode_source"] == "console",
               body)
        expect(json.load(open(modes_file)) == {"www.a.test": "shadow"},
               "modes file")
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/admin/panel")
        expect(status == 200, status)
        status, _ = admin_call(admin_socket, "DELETE", "/policy/www.a.test")
        expect(status == 200, status)
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/admin/panel")
        expect(status == 403, status)

        # Console settings (ADR-018): a live key applies at once from the
        # layer file, a reset gives the main file back.
        status, body = admin_call(admin_socket, "GET", "/settings")
        expect(status == 200 and body["editable"], body)
        status, body = admin_call(admin_socket, "POST", "/settings", {
            "base_revision": body["revision"],
            "set": {"policy.block_status": 451, "captcha.rounds": 3}})
        expect(status == 200 and len(body["changes"]) == 2, body)
        expect(os.stat(settings_file).st_mode & 0o777 == 0o600, "layer mode")
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/admin/panel")
        expect(status == 451, status)
        _, body = admin_call(admin_socket, "GET", "/settings")
        rounds = next(k for k in body["keys"] if k["path"] == "captcha.rounds")
        expect(rounds["pending_restart"] and rounds["source"] == "console",
               rounds)
        status, body = admin_call(admin_socket, "POST", "/settings", {
            "base_revision": body["revision"],
            "reset": ["policy.block_status", "captcha.rounds"]})
        expect(status == 200, body)
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/admin/panel")
        expect(status == 403, status)

        # The verdict set in effect and a rule checked on sample events.
        status, body = admin_call(admin_socket, "GET", "/config")
        expect(status == 200 and any(r["name"] == "admin"
                                     for r in body["rules"]), body)
        status, body = admin_call(admin_socket, "POST", "/rules/test", {
            "when": 'path ~ "/admin*"',
            "samples": [{"path": "/admin/x"}, {"path": "/home"}]})
        expect(status == 200 and body["matched"] == [0], body)
        # A body that arrives after the head (the console's samples): the
        # request line once pointed into the buffer the body reallocated.
        samples = [{"path": f"/page/{i}", "user_agent": "x" * 40}
                   for i in range(2000)] + [{"path": "/admin/y"}]
        status, body = admin_call(admin_socket, "POST", "/rules/test", {
            "when": 'path ~ "/admin*"', "samples": samples})
        expect(status == 200 and body["matched"] == [2000],
               (status, str(body)[:200]))

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

    def grpc_trailers_only():
        # gRPC "trailers-only" answers (an error status without a body) must
        # stay one HEADERS frame with END_STREAM; split into HEADERS + empty
        # DATA, gRPC clients report "closed the stream without trailers".
        result = subprocess.run(
            ["curl", "-sS", "--http2", "-v", "--trace-config", "http/2",
             "--resolve", f"a.test:{https_port}:127.0.0.1", "--cacert", ca_a,
             "-H", "content-type: application/grpc", "-H", "te: trailers",
             "--data-binary", "x", "-o", os.devnull,
             f"https://a.test:{https_port}/trailers-only"],
            capture_output=True, text=True, timeout=30)
        frames = [line for line in result.stderr.splitlines()
                  if "<- FRAME[" in line and "[1]" in line]
        expect(frames and "HEADERS" in frames[0] and "eos=1" in frames[0],
               frames or result.stderr[-2000:])
        expect(not any("DATA" in f for f in frames), frames)
        expect("grpc-status: 12" in result.stderr, result.stderr[-2000:])

    def http3():
        if "HTTP3" not in subprocess.run(["curl", "-V"], capture_output=True,
                                         text=True).stdout:
            print("  (skipped: curl without HTTP/3)")
            return
        out = os.path.join(workdir, "h3-body")

        def h3(path, host="a.test", extra=()):
            result = subprocess.run(
                ["curl", "-sS", "--http3-only", "--resolve",
                 f"{host}:{https_port}:127.0.0.1", "--cacert", ca_a,
                 "-o", out, "-w", "%{http_code} %{http_version}", *extra,
                 f"https://{host}:{https_port}{path}"],
                capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                raise AssertionError(f"curl h3 failed: {result.stderr}")
            status, version = result.stdout.split()
            return int(status), version

        # One handshake, one connection: curl closes it when done, so the
        # gauge is back where it was. A ClientHello split over two Initial
        # datagrams once made a second, lingering connection.
        before = read_metrics(metrics_url)["bot_shield_quic_connections"]
        status, version = h3("/h3/get?x=1")
        expect(status == 200 and version == "3", (status, version))
        time.sleep(0.5)
        after = read_metrics(metrics_url)["bot_shield_quic_connections"]
        expect(after <= before, (before, after))
        body = json.loads(open(out).read())
        expect(body["proto"] == "h2", body)  # Upstream leg: the h2 pool.
        expect("x-bot-score" in body["headers"], body)
        expect(body["headers"]["x-forwarded-for"] == "127.0.0.1", body)
        # Upload and big download.
        upload = os.path.join(workdir, "h3-upload")
        with open(upload, "wb") as f:
            f.write(os.urandom(2 * 1024 * 1024))
        status, _ = h3("/h3/upload", extra=("--data-binary", f"@{upload}"))
        expect(status == 200 and json.loads(open(out).read())["body_len"]
               == 2 * 1024 * 1024, open(out).read()[:200])
        # 2 MB: curl's OpenSSL QUIC backend now and then stops raising the
        # stream window around 2.5 MB (its connection window keeps growing);
        # larger HTTP/3 downloads were checked with aioquic and Traefik.
        status, _ = h3("/big?bytes=2000000")
        expect(status == 200 and os.path.getsize(out) == 2000000,
               os.path.getsize(out))
        # Verdicts: enforce host blocks over HTTP/3 too.
        status, _ = h3("/admin/x", host="www.a.test", extra=("-k",))
        expect(status == 403, status)
        # The connection event carries the QUIC fingerprints.
        event = nats.find("e2e.events.conn",
                          lambda e: e.get("listener") == "quic")
        expect(event["ja4"].startswith("q13"), event)
        expect(event.get("quic_fp"), event)
        # TCP responses advertise HTTP/3.
        _, headers, _ = h1_get(https_port, "a.test", ca_a, "/alt")
        expect(headers.get("alt-svc") == f'h3=":{https_port}"; ma=86400',
               headers)
        # No certificate for the name: QUIC refused, the client must use TCP.
        result = subprocess.run(
            ["curl", "-sS", "--http3-only", "-k", "--max-time", "5",
             "--resolve", f"b.test:{https_port}:127.0.0.1",
             f"https://b.test:{https_port}/"],
            capture_output=True, text=True, timeout=30)
        expect(result.returncode != 0, result.stdout)

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
        # Round trips (TLS 1.3 with curl): loopback, so tiny, not relayed.
        expect(0 < event["handshake_us"] < 2_000_000, event)
        if "tcp_rtt_us" in event:  # 0 on some loopbacks: then left out
            expect(event["tcp_rtt_us"] < 2_000_000, event)
        expect("relayed_connection" not in event.get("reasons", []), event)

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

    def events_model_features():
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/tagged")
        expect(len(event["features"]) == 40, event.get("features"))
        expect(0 <= event["model_score"] <= 1, event.get("model_score"))

    def events_keep_secrets():
        for payload in nats.payloads():
            expect("secret" not in payload, payload)
            expect("127.0.0.1" not in payload, payload)
            expect("6.6.6.6" not in payload, payload)

    def under_attack():
        html = b"Accept: text/html\r\n"
        status, data = admin_call(admin_socket, "POST", "/attack",
                                  {"host": "a.test", "ttl": "5m"})
        expect(status == 201 and data["host"] == "a.test", (status, data))
        # a.test is a shadow host, yet everyone without a token is challenged.
        status, headers, body = h1_get(https_port, "a.test", ca_a,
                                       "/attack/page", html)
        expect(status == 403 and headers["content-type"].startswith(
            "text/html"), (status, headers))
        status, _, api = h1_get(https_port, "a.test", ca_a, "/attack/api")
        expect(status == 403 and b"challenge_required" in api, (status, api))
        event = nats.find("e2e.events.req",
                          lambda e: e.get("path_group") == "/attack/page")
        expect("under_attack" in event["reasons"], event)
        # Explicit allows (rules) and other hosts pass.
        status, _, _ = h1_get(https_port, "a.test", ca_a, "/attack/monitor",
                              b"X-Monitor: e2e-token\r\n")
        expect(status == 200, status)
        status, _, _ = h1_get(https_port, "www.a.test", ca_a, "/attack/other",
                              html)
        expect(status == 200, status)
        # A solved challenge lets the client through.
        verify = solve_challenge(body.decode())
        status, headers, _ = h1_get(https_port, "a.test", ca_a, verify)
        expect(status == 302, status)
        cookie = headers["set-cookie"].split(";")[0]
        status, _, body = h1_get(https_port, "a.test", ca_a, "/attack/page",
                                 html + f"Cookie: {cookie}\r\n".encode())
        expect(status == 200, (status, body))
        status, data = admin_call(admin_socket, "GET", "/attack")
        expect([e["host"] for e in data["entries"]] == ["a.test"], data)
        # The entry reaches its file within a second (off the workers).
        for _ in range(40):
            if os.path.exists(attack_file) and [
                    e["host"] for e in json.load(open(attack_file))["entries"]
            ] == ["a.test"]:
                break
            time.sleep(0.05)
        else:
            expect(False, "attack file not written")
        status, _ = admin_call(admin_socket, "DELETE", "/attack/a.test")
        expect(status == 200, status)
        status, data = admin_call(admin_socket, "GET", "/attack")
        expect(data["entries"] == [] and data["history"][0]["host"] == "a.test"
               and "ended" in data["history"][0], data)
        status, _, _ = h1_get(https_port, "a.test", ca_a, "/attack/page", html)
        expect(status == 200, status)

    def challenge_endpoint_limit():
        # /__bs/* is answered here: its own per-IP limit (default 30/m,
        # burst 10), not the request rate limits.
        statuses = [h1_get(https_port, "a.test", ca_a,
                           "/__bs/challenge?r=%2F")[0] for _ in range(15)]
        # The budget refills (one per 2 s): a slow (sanitizer) build may see
        # a 200 again at the end; earlier checks may have used some of it.
        expect(statuses[0] == 200 and 429 in statuses, statuses)
        status, _, _ = h1_get(https_port, "a.test", ca_a, "/after-bs")
        expect(status == 200, status)

    def no_sni_rejected():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", https_port), timeout=5)
        try:
            with context.wrap_socket(raw, server_hostname=None) as tls:
                tls.sendall(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
                expect(tls.recv(1024) == b"", "served without SNI")
        except (ssl.SSLError, ConnectionError):
            pass

    def h2_rapid_reset():
        with h2_connect(https_port, "a.test", ca_a) as tls:
            burst = b""
            for i in range(300):
                stream = 1 + 2 * i
                burst += h2_frame(H2_HEADERS, H2_END_HEADERS, stream,
                                  h2_request_block("a.test", "/reset"))
                burst += h2_frame(H2_RST_STREAM, 0, stream,
                                  struct.pack(">I", 8))  # CANCEL
            try:
                tls.sendall(burst)
            except (ConnectionError, ssl.SSLError):
                pass
            frames = h2_read_frames(tls)
        goaway = [f for f in frames if f[0] == H2_GOAWAY]
        expect(goaway, [f[0] for f in frames][:20])
        last_stream, code = struct.unpack(">II", goaway[0][3][:8])
        expect(code != 0 and last_stream < 599, (last_stream, code))

    def metrics_exposed():
        values = read_metrics(metrics_url)
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
        expect(values["bot_shield_rules_matched_total"] >= 3, "rule matches")
        expect(values["bot_shield_label_hosts"] == 4, "label hosts")
        expect(values['bot_shield_rate_limited_total{mode="enforce"}'] >= 2,
               "rate limited")
        expect(values['bot_shield_rate_limited_total{mode="shadow"}'] >= 2,
               "rate limited in shadow")
        expect(values['bot_shield_connections_rejected_total'
                      '{reason="client_hello_timeout"}'] >= 1, "timeout count")
        expect(values['bot_shield_challenges_total{result="passed"}'] == 2,
               "challenges passed")
        expect(values['bot_shield_challenges_total{result="failed"}'] == 1,
               "challenges failed")
        expect(values['bot_shield_challenges_total{result="would"}'] >= 1,
               "challenges would")
        expect(values["bot_shield_tokens_valid_total"] >= 2, "tokens valid")
        expect(values['bot_shield_crawler_checks_total{result="failed"}'] >= 1,
               "crawler checks")
        expect(values["bot_shield_honeypot_hits_total"] >= 2, "honeypot")
        expect(values['bot_shield_tarpits_total{result="started"}'] == 3,
               "tarpits")
        expect(values["bot_shield_tarpits_active"] == 0, "tarpits active")
        # HTML twice (the labyrinth is asked again) and JSON once.
        expect(values["bot_shield_decoys_total"] == 3, "decoys")
        expect(values["bot_shield_behavior_signals_total"] >= 2, "behavior")
        expect(values["bot_shield_nats_connected"] == 1, "nats connected")
        expect(values['bot_shield_events_total{result="published"}'] >= 50,
               "events published")
        expect(values['bot_shield_connections_rejected_total'
                      '{reason="no_server_name"}'] >= 1, "no SNI rejected")
        expect(values["bot_shield_h2_client_resets_total"] >= 100, "resets")
        expect(values["bot_shield_attack_challenges_total"] >= 2, "attack")
        expect(values["bot_shield_attack_hosts"] == 0, "attack hosts")
        expect(values["bot_shield_challenge_endpoint_limited_total"] >= 1,
               "challenge endpoint limit")

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
        ("rules: allow and block override verdicts", rules_override_verdicts),
        ("challenge: page, PoW in node, token, cookie stripped", js_challenge),
        ("challenge: soft signals escalate to the CAPTCHA",
         challenge_escalation),
        ("captcha: Turnstile, deferred siteverify over h1 and h2",
         captcha_turnstile),
        ("asn: database download, rule field, event", asn_database),
        ("web bot auth: Ed25519 signature, key directory over HTTPS",
         web_bot_auth),
        ("crawlers: AI policy, fake Googlebot by reverse DNS", crawlers),
        ("honeypot marks, sequential IDs", honeypot_and_behavior),
        ("tarpit (h1, h2, client leaves) and decoy with watermark",
         tarpit_and_decoy),
        ("throttle action: own limit, enforce and shadow", throttle),
        ("hot reload: SIGHUP, POST /reload, broken file kept out", hot_reload),
        ("whoami: text, JSON, page; answered, not blocked; reloadable",
         whoami),
        ("rate limits: 429, shadow, API keys, allow bypass", rate_limits),
        ("rate limits on origin responses: only 401s count",
         rate_limits_on_responses),
        ("rules: query() and has_cookie()", rules_on_query_and_cookies),
        ("docker labels: mode, limits, passthrough, off, precedence, reload",
         docker_labels),
        ("admin API: status, policy, lists, decisions, console modes",
         admin_api),
        ("under attack: challenge without token, admin switch", under_attack),
        ("/__bs/* endpoints: own per-IP limit", challenge_endpoint_limit),
        ("ClientHello without SNI rejected", no_sni_rejected),
        ("h2: rapid reset ends in GOAWAY", h2_rapid_reset),
        ("h2: gRPC trailers-only answer stays one frame", grpc_trailers_only),
        ("h3: GET, upload, download, verdicts, Alt-Svc, fallback", http3),
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
        ("events: model features and score", events_model_features),
        ("metrics", metrics_exposed),
    ]:
        checks.run(name, fn)

    def fail_open_watchdog():
        watchdog_binary = os.path.join(os.path.dirname(binary),
                                       "bot-shield-watchdog")
        state = os.path.join(workdir, "failopen-state")
        textfile = os.path.join(workdir, "failopen.prom")
        health = urllib.request.urlopen(metrics_url + "/health", timeout=2)
        expect(health.status == 200, health.status)
        watchdog = subprocess.Popen(
            [watchdog_binary, "--health", f"127.0.0.1:{metrics_port}",
             "--interval", "100ms", "--timeout", "300ms", "--fail-after", "3",
             "--recover-after", "2",
             "--on-fail", f"echo open > {state}",
             "--on-recover", f"echo closed > {state}",
             "--state-file", textfile,
             # An unreadable config costs only the notifications.
             "--config", os.path.join(workdir, "missing.yaml")],
            stdout=log_file, stderr=subprocess.STDOUT)

        def wait_state(expected):
            for _ in range(100):
                if (os.path.exists(state) and
                        open(state).read().strip() == expected):
                    return
                time.sleep(0.05)
            raise AssertionError(f"state is not {expected}")

        try:
            # Unknown at start: the first decision is applied.
            wait_state("closed")
            # A hung gateway (stopped process) fails open, then recovers.
            process.send_signal(signal.SIGSTOP)
            try:
                wait_state("open")
                expect("bot_shield_failopen_active 1" in open(textfile).read(),
                       "textfile")
            finally:
                process.send_signal(signal.SIGCONT)
            wait_state("closed")
        finally:
            watchdog.terminate()
            expect(watchdog.wait(timeout=5) == 0, "watchdog exit code")

    checks.run("fail-open watchdog: hang, redirect, recovery",
               fail_open_watchdog)

    def graceful_shutdown():
        # Under-attack mode survives the restart: written on the way out.
        status, _ = admin_call(admin_socket, "POST", "/attack",
                               {"host": "www.a.test"})
        expect(status == 201, status)
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        code = process.wait(timeout=10)
        expect(code == 0, f"exit code {code}")
        elapsed = time.monotonic() - started
        expect(elapsed < 5, f"shutdown took {elapsed:.1f}s")
        state = json.load(open(attack_file))
        expect([e["host"] for e in state["entries"]] == ["www.a.test"], state)

    checks.run("graceful shutdown (pool drained)", graceful_shutdown)

    def connection_limits():
        port = free_port()
        # Its own acme.json: the shared one was deliberately broken above.
        limited_acme = os.path.join(workdir, "limited-acme.json")
        write_atomic(limited_acme, acme_json([(*gw_a, "a.test")]))
        limited_config = os.path.join(workdir, "limited.yaml")
        with open(limited_config, "w") as f:
            f.write(f"""
listen:
  https: 127.0.0.1:{port}
  http: ""
traefik:
  acme_json: {limited_acme}
  upstream_https: 127.0.0.1:{tls_port}
connection_limits:
  new_per_ip: 3/m
  new_burst_per_ip: 3
metrics:
  listen: ""
{OFFLINE}""")
        limited = subprocess.Popen([binary, "--config", limited_config],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        try:
            wait_port(port)  # Uses one connection of the burst.
            for _ in range(2):
                status, _, _ = h1_get(port, "a.test", ca_a, "/")
                expect(status == 200, status)
            # The fourth connection from this IP is closed before TLS.
            try:
                h1_get(port, "a.test", ca_a, "/")
                raise AssertionError("connection over the limit was served")
            except (ssl.SSLError, ConnectionError, OSError):
                pass
        finally:
            limited.send_signal(signal.SIGTERM)
            limited.wait(timeout=10)

    checks.run("connection limits: new connections per IP", connection_limits)

    def strict_limits_in_valkey():
        server = shutil.which("valkey-server") or shutil.which("redis-server")
        if server is None:
            print("SKIP strict limits: no valkey-server")
            return
        valkey_port = free_port()
        valkey = subprocess.Popen(
            [server, "--port", str(valkey_port), "--bind", "127.0.0.1",
             "--save", "", "--appendonly", "no"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        gateways = []
        try:
            wait_port(valkey_port)
            ports = []
            for name in ("one", "two"):
                port = free_port()
                ports.append(port)
                acme = os.path.join(workdir, f"strict-{name}-acme.json")
                write_atomic(acme, acme_json([(*gw_a, "a.test")]))
                config = os.path.join(workdir, f"strict-{name}.yaml")
                with open(config, "w") as f:
                    f.write(f"""
listen:
  https: 127.0.0.1:{port}
  http: ""
traefik:
  acme_json: {acme}
  upstream_https: 127.0.0.1:{tls_port}
mode: enforce
rate_limits:
  - name: strict-login
    paths: [/strict*]
    key: [ip]
    rate: 3/m
    burst: 3
    mode: strict
valkey:
  address: 127.0.0.1:{valkey_port}
  timeout: 500ms
metrics:
  listen: ""
{OFFLINE}""")
                gateways.append(subprocess.Popen(
                    [binary, "--config", config],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            for port in ports:
                wait_port(port)
            time.sleep(0.3)  # Both connect to Valkey.
            # One limit over two gateways: the fourth request is refused
            # wherever it lands. The first carries a body, held until
            # Valkey answers and then sent on.
            body = b"x" * 20000
            results = h1_exchange(
                ports[0], "a.test", ca_a,
                b"POST /strict/1 HTTP/1.1\r\nHost: a.test\r\n"
                b"Content-Length: 20000\r\n\r\n" + body)
            expect(results[0][0] == 200 and
                   json.loads(results[0][2])["body_len"] == 20000, results)
            statuses = [h1_get(ports[i % 2], "a.test", ca_a,
                               f"/strict/{i}")[0] for i in range(1, 4)]
            expect(statuses == [200, 200, 429], statuses)
        finally:
            for gateway in gateways:
                gateway.send_signal(signal.SIGTERM)
                gateway.wait(timeout=10)
            valkey.terminate()
            valkey.wait(timeout=10)

    checks.run("rate limits: strict, shared through Valkey",
               strict_limits_in_valkey)

    def notifications():
        hook = FakeHttp({"/hook": lambda method, query, body:
                         (200, "text/plain", b"ok")})

        def events():
            return [json.loads(body) for method, path, body in hook.requests
                    if method == "POST" and path == "/hook"]

        def wait_event(name, timeout=10):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                found = [e for e in events() if e["event"] == name]
                if found:
                    return found
                time.sleep(0.05)
            raise AssertionError(f"no {name} notification: {events()}")

        port, metrics = free_port(), free_port()
        notify_acme = os.path.join(workdir, "notify-acme.json")
        write_atomic(notify_acme, acme_json([(*gw_a, "a.test")]))
        notify_config = os.path.join(workdir, "notify.yaml")
        config_text = f"""
listen:
  https: 127.0.0.1:{port}
  http: ""
traefik:
  acme_json: {notify_acme}
  upstream_https: 127.0.0.1:{tls_port}
attack:
  auto_rps: 5
  auto_duration: 1m
notify:
  name: e2e
  webhook: http://127.0.0.1:{hook.port}/hook
  repeat_after: 1h
metrics:
  listen: 127.0.0.1:{metrics}
{OFFLINE}"""
        with open(notify_config, "w") as f:
            f.write(config_text)
        notifying = subprocess.Popen([binary, "--config", notify_config],
                                     stdout=log_file, stderr=subprocess.STDOUT)
        watchdog = None
        try:
            wait_port(port)
            # A flood well past auto_rps (a burst of ten seconds' worth)
            # switches the host on: one notification, not one per request.
            # The reader holds the socket open: closed with it.
            with tls_socket(port, "a.test", ca_a, ["http/1.1"]) as tls, \
                    tls.makefile("rb") as reader:
                for _ in range(90):
                    tls.sendall(b"GET /flood HTTP/1.1\r\nHost: a.test\r\n\r\n")
                    response = http.client.HTTPResponse(_Buffered(reader))
                    response.begin()
                    response.read()
            attack = wait_event("attack_auto")[0]
            expect(attack["host"] == "a.test", attack)
            expect(attack["name"] == "e2e", attack)
            # One client floods: only its network is put under attack.
            expect(attack["text"].startswith(
                "bot-shield e2e: under-attack mode on for network "
                "127.0.0.0/24 on a.test for 1m"), attack)
            expect(isinstance(attack["ts"], int), attack)

            # A broken file on SIGHUP: rejected, and the operator hears.
            with open(notify_config, "w") as f:
                f.write(config_text + "rules: [{name: x}]\n")
            notifying.send_signal(signal.SIGHUP)
            failed = wait_event("reload_failed")[0]
            expect("rules" in failed["text"], failed)
            expect(failed["host"] is None, failed)
            with open(notify_config, "w") as f:
                f.write(config_text)

            # The watchdog tells about fail-open itself (the gateway is
            # down then); its start is no news.
            watchdog = subprocess.Popen(
                [os.path.join(os.path.dirname(binary), "bot-shield-watchdog"),
                 "--health", f"127.0.0.1:{metrics}", "--interval", "100ms",
                 "--timeout", "300ms", "--fail-after", "3",
                 "--recover-after", "2", "--on-fail", "true",
                 "--on-recover", "true", "--config", notify_config],
                stdout=log_file, stderr=subprocess.STDOUT)
            time.sleep(1)
            expect(not [e for e in events() if e["event"].startswith(
                "failopen")], events())
            notifying.send_signal(signal.SIGSTOP)
            try:
                on = wait_event("failopen_on")[0]
                expect("without filtering" in on["text"], on)
            finally:
                notifying.send_signal(signal.SIGCONT)
            off = wait_event("failopen_off")[0]
            expect("bypassed for" in off["text"], off)
            expect(len([e for e in events()
                        if e["event"] == "attack_auto"]) == 1, events())
        finally:
            if watchdog:
                watchdog.terminate()
                watchdog.wait(timeout=5)
            notifying.send_signal(signal.SIGTERM)
            notifying.wait(timeout=10)
            hook.server.shutdown()

    checks.run("notifications: attack, reload, fail-open", notifications)

    # A gateway with tight protection settings of its own.
    guarded_port, guarded_metrics = free_port(), free_port()
    guarded_acme = os.path.join(workdir, "guarded-acme.json")
    write_atomic(guarded_acme, acme_json([(*gw_a, "a.test")]))
    guarded_config = os.path.join(workdir, "guarded.yaml")
    with open(guarded_config, "w") as f:
        f.write(f"""
listen:
  https: 127.0.0.1:{guarded_port}
  http: ""
traefik:
  acme_json: {guarded_acme}
  upstream_https: 127.0.0.1:{tls_port}
timeouts:
  request_headers: 1s
  request_body: 1s
  request_body_min_rate: 1000
max_requests_per_connection: 5
connection_limits:
  pending_per_ip: 2
metrics:
  listen: 127.0.0.1:{guarded_metrics}
{OFFLINE}""")
    guarded = subprocess.Popen([binary, "--config", guarded_config],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    wait_port(guarded_port)

    def h1_request_headers_timeout():
        # Silent after the handshake: closed after request_headers.
        with tls_socket(guarded_port, "a.test", ca_a, ["http/1.1"]) as tls:
            elapsed = wait_closed(tls, 5)
        expect(0.8 < elapsed < 3, f"closed after {elapsed:.1f}s")
        # Slowloris: a header line every 300 ms never completes the head.
        with tls_socket(guarded_port, "a.test", ca_a, ["http/1.1"]) as tls:
            started = time.monotonic()
            tls.sendall(b"GET / HTTP/1.1\r\nHost: a.test\r\n")
            closed = False
            for i in range(20):
                time.sleep(0.3)
                try:
                    tls.sendall(f"X-Slow-{i}: 1\r\n".encode())
                except (ConnectionError, ssl.SSLError):
                    closed = True
                    break
            if not closed:
                wait_closed(tls, 2)
            elapsed = time.monotonic() - started
        expect(elapsed < 3, f"slowloris lasted {elapsed:.1f}s")
        # Keep-alive: idling between requests is fine, the next head gets
        # its own deadline.
        with tls_socket(guarded_port, "a.test", ca_a, ["http/1.1"]) as tls:
            reader = tls.makefile("rb")
            for _ in range(2):
                tls.sendall(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
                response = http.client.HTTPResponse(_Buffered(reader))
                response.begin()
                response.read()
                expect(response.status == 200, response.status)
                time.sleep(1.5)

    def h2_request_headers_timeout():
        with h2_connect(guarded_port, "a.test", ca_a) as tls:
            started = time.monotonic()
            frames = h2_read_frames(tls, timeout=5)
            elapsed = time.monotonic() - started
        expect(0.8 < elapsed < 3, f"closed after {elapsed:.1f}s")
        expect(frames and frames[0][0] == H2_SETTINGS, frames)
        # A header block left open (no END_HEADERS) after the first request.
        with h2_connect(guarded_port, "a.test", ca_a) as tls:
            tls.sendall(h2_frame(H2_HEADERS, H2_END_HEADERS | H2_END_STREAM,
                                 1, h2_request_block("a.test")) +
                        h2_frame(H2_HEADERS, 0, 3,
                                 h2_request_block("a.test")))
            started = time.monotonic()
            frames = h2_read_frames(tls, timeout=5)
            elapsed = time.monotonic() - started
        expect(any(f[0] == H2_HEADERS and f[2] == 1 for f in frames), frames)
        expect(elapsed < 3, f"open header block lasted {elapsed:.1f}s")

    def h1_request_body_rate():
        # A body that trickles in below the minimum rate is cut off.
        with tls_socket(guarded_port, "a.test", ca_a, ["http/1.1"]) as tls:
            started = time.monotonic()
            tls.sendall(b"POST /slow HTTP/1.1\r\nHost: a.test\r\n"
                        b"Content-Length: 100000\r\n\r\n")
            closed = False
            for _ in range(30):
                time.sleep(0.3)
                try:
                    tls.sendall(b"x" * 10)
                except (ConnectionError, ssl.SSLError):
                    closed = True
                    break
            if not closed:
                wait_closed(tls, 2)
            elapsed = time.monotonic() - started
        expect(elapsed < 4, f"slow body lasted {elapsed:.1f}s")
        # A body above the rate goes through, however long it is in total.
        body = b"y" * 3000
        with tls_socket(guarded_port, "a.test", ca_a, ["http/1.1"]) as tls:
            tls.sendall(b"POST /steady HTTP/1.1\r\nHost: a.test\r\n"
                        b"Content-Length: 3000\r\n\r\n")
            for i in range(0, len(body), 500):
                time.sleep(0.25)
                tls.sendall(body[i:i + 500])
            response = http.client.HTTPResponse(tls)
            response.begin()
            expect(response.status == 200, response.status)
            expect(json.loads(response.read())["body_len"] == 3000,
                   "body length")

    def h2_request_body_rate():
        # POST without END_STREAM, then 10 bytes every 300 ms: RST_STREAM.
        block = (b"\x83\x87\x04\x05/slow\x01" + bytes([len("a.test")]) +
                 b"a.test")
        with h2_connect(guarded_port, "a.test", ca_a) as tls:
            tls.sendall(h2_frame(H2_HEADERS, H2_END_HEADERS, 1, block))
            tls.settimeout(0.3)
            started = time.monotonic()
            data = b""
            reset = None
            while reset is None and time.monotonic() - started < 6:
                try:
                    tls.sendall(h2_frame(H2_DATA, 0, 1, b"x" * 10))
                    data += tls.recv(65536)
                except (TimeoutError, socket.timeout):
                    pass
                except (ConnectionError, ssl.SSLError):
                    break
                while len(data) >= 9:
                    length = int.from_bytes(data[:3], "big")
                    if len(data) < 9 + length:
                        break
                    if data[3] == H2_RST_STREAM:
                        reset = time.monotonic() - started
                    data = data[9 + length:]
        expect(reset is not None and reset < 4, f"reset after {reset}")

    def requests_per_connection():
        raw = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n" * 5
        results = h1_exchange(guarded_port, "a.test", ca_a, raw, responses=5)
        expect([r[0] for r in results] == [200] * 5, results)
        expect(all(r[1].get("connection") != "close" for r in results[:4]),
               results)
        expect(results[4][1].get("connection") == "close", results[4][1])
        with h2_connect(guarded_port, "a.test", ca_a) as tls:
            tls.sendall(b"".join(
                h2_frame(H2_HEADERS, H2_END_HEADERS | H2_END_STREAM, 1 + 2 * i,
                         h2_request_block("a.test", f"/r{i}"))
                for i in range(8)))
            frames = h2_read_frames(tls)
        goaway = [f for f in frames if f[0] == H2_GOAWAY]
        expect(goaway, [f[0] for f in frames])
        last_stream, code = struct.unpack(">II", goaway[0][3][:8])
        expect((last_stream, code) == (9, 0), (last_stream, code))
        answered = sorted({f[2] for f in frames if f[0] == H2_HEADERS})
        expect(answered == [1, 3, 5, 7, 9], answered)

    def pending_per_ip():
        # Two connections that never send a ClientHello hold both slots.
        held = [socket.create_connection(("127.0.0.1", guarded_port),
                                         timeout=5) for _ in range(2)]
        time.sleep(0.2)
        try:
            with socket.create_connection(("127.0.0.1", guarded_port),
                                          timeout=5) as third:
                elapsed = wait_closed(third, 2)
            expect(elapsed < 0.5, f"third connection open {elapsed:.1f}s")
        finally:
            for s in held:
                s.close()
        time.sleep(0.2)
        status, _, _ = h1_get(guarded_port, "a.test", ca_a, "/")
        expect(status == 200, status)
        values = read_metrics(f"http://127.0.0.1:{guarded_metrics}")
        expect(values['bot_shield_connections_rejected_total'
                      '{reason="pending_per_ip"}'] >= 1, "pending rejections")
        expect(values["bot_shield_request_header_timeouts_total"] >= 4,
               "header timeouts")
        expect(values["bot_shield_connection_request_limit_total"] >= 2,
               "request limits")
        expect(values["bot_shield_request_body_timeouts_total"] >= 2,
               "body timeouts")

    try:
        for name, fn in [
            ("timeouts: h1 request headers (silent, slowloris)",
             h1_request_headers_timeout),
            ("timeouts: h2 first request and open header block",
             h2_request_headers_timeout),
            ("timeouts: h1 request body below the minimum rate",
             h1_request_body_rate),
            ("timeouts: h2 request body below the minimum rate",
             h2_request_body_rate),
            ("limits: requests per connection (h1 close, h2 GOAWAY)",
             requests_per_connection),
            ("limits: pending connections per IP", pending_per_ip),
        ]:
            checks.run(name, fn)
    finally:
        guarded.send_signal(signal.SIGTERM)
        guarded.wait(timeout=10)
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
