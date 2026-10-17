#!/usr/bin/env python3
"""End-to-end test: runs the bot-shield binary in front of a fake Traefik.

The fake upstream requires a PROXY v2 header on every connection, then (on the
TLS port) completes a TLS handshake with its own certificate and answers one
line describing what it saw. Gateway certificates and upstream certificates
are different, so a client can tell whether bot-shield terminated TLS (the
gateway certificate validates) or passed it through (the upstream one does).

Usage: run_e2e.py path/to/bot-shield
"""

import base64
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

PROXY_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


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


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("eof while reading PROXY header")
        data += chunk
    return data


def read_proxy_v2(sock):
    header = recv_exact(sock, 16)
    if header[:12] != PROXY_SIGNATURE:
        raise ValueError("missing PROXY v2 signature")
    family, length = header[13], struct.unpack("!H", header[14:16])[0]
    body = recv_exact(sock, length)
    if family == 0x11:
        src = socket.inet_ntop(socket.AF_INET, body[0:4])
        src_port = struct.unpack("!H", body[8:10])[0]
        tlvs = body[12:]
    else:
        src = socket.inet_ntop(socket.AF_INET6, body[0:16])
        src_port = struct.unpack("!H", body[32:34])[0]
        tlvs = body[36:]
    authority = ""
    while len(tlvs) >= 3:
        kind, size = tlvs[0], struct.unpack("!H", tlvs[1:3])[0]
        if kind == 0x02:
            authority = tlvs[3:3 + size].decode()
        tlvs = tlvs[3 + size:]
    return src, src_port, authority


class FakeTraefik:
    """TLS and plain listeners that require PROXY v2 and report what they saw."""

    def __init__(self, cert, key):
        self.tls_port = free_port()
        self.http_port = free_port()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.context.set_alpn_protocols(["h2", "http/1.1", "acme-tls/1"])
        self.sni = threading.local()
        self.context.sni_callback = self._on_sni
        for port, tls in ((self.tls_port, True), (self.http_port, False)):
            listener = socket.create_server(("127.0.0.1", port))
            threading.Thread(target=self._accept, args=(listener, tls),
                             daemon=True).start()

    def _on_sni(self, ssl_socket, server_name, _context):
        ssl_socket.sni_seen = server_name or ""

    def _accept(self, listener, tls):
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=self._serve, args=(conn, tls),
                             daemon=True).start()

    def _serve(self, conn, tls):
        try:
            conn.settimeout(5)
            src, src_port, authority = read_proxy_v2(conn)
            alpn, sni = "-", "-"
            if tls:
                conn = self.context.wrap_socket(conn, server_side=True)
                alpn = conn.selected_alpn_protocol() or "-"
                sni = getattr(conn, "sni_seen", "") or "-"
            line = conn.recv(1024).split(b"\n")[0].decode()
            reply = (f"upstream={'tls' if tls else 'plain'} src={src}:{src_port} "
                     f"sni={sni} alpn={alpn} authority={authority or '-'} "
                     f"got={line}\n")
            conn.sendall(reply.encode())
        except Exception as e:  # noqa: BLE001 - report and drop the connection
            print(f"fake traefik: {e}", file=sys.stderr)
        finally:
            conn.close()


def parse_reply(reply):
    return dict(item.split("=", 1) for item in reply.strip().split(" "))


def tls_request(port, server_name, cafile, alpn=None):
    context = ssl.create_default_context(cafile=cafile)
    if alpn:
        context.set_alpn_protocols(alpn)
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    with context.wrap_socket(raw, server_hostname=server_name) as tls:
        local_port = tls.getsockname()[1]
        negotiated = tls.selected_alpn_protocol()
        tls.sendall(b"hello\n")
        reply = tls.recv(4096).decode()
    fields = parse_reply(reply)
    return fields, local_port, negotiated


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
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    binary = os.path.abspath(sys.argv[1])
    workdir = tempfile.mkdtemp(prefix="bot-shield-e2e-")

    gw_a = make_cert(workdir, "gw-a", ["a.test", "www.a.test"])
    gw_w = make_cert(workdir, "gw-w", ["*.w.test"])
    gw_c = make_cert(workdir, "gw-c", ["c.test"])
    upstream = make_cert(workdir, "upstream",
                         ["a.test", "b.test", "c.test", "grpc.a.test"])
    acme_path = os.path.join(workdir, "acme.json")
    write_atomic(acme_path, acme_json([(*gw_a, "a.test"), (*gw_w, "*.w.test")]))

    traefik = FakeTraefik(*upstream)
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
  upstream_https: 127.0.0.1:{traefik.tls_port}
  upstream_http: 127.0.0.1:{traefik.http_port}
passthrough_hosts: [grpc.a.test]
timeouts:
  client_hello: 1s
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
        sys.exit("bot-shield did not start; log: " + open(log_path).read())

    gw_a_cert, gw_w_cert, gw_c_cert, upstream_cert = (
        gw_a[0], gw_w[0], gw_c[0], upstream[0])
    checks = Checks()

    def terminate_http11():
        fields, local_port, alpn = tls_request(https_port, "a.test", gw_a_cert,
                                               ["http/1.1"])
        expect(alpn == "http/1.1", f"client ALPN {alpn}")
        expect(fields["upstream"] == "tls", fields)
        expect(fields["sni"] == "a.test", fields)
        expect(fields["alpn"] == "http/1.1", fields)
        expect(fields["src"] == f"127.0.0.1:{local_port}", fields)
        expect(fields["authority"] == "a.test", fields)
        expect(fields["got"] == "hello", fields)

    def terminate_h2():
        fields, _, alpn = tls_request(https_port, "www.a.test", gw_a_cert,
                                      ["h2", "http/1.1"])
        expect(alpn == "h2", f"client ALPN {alpn}")
        expect(fields["alpn"] == "h2", fields)
        expect(fields["sni"] == "www.a.test", fields)

    def terminate_without_alpn():
        fields, _, alpn = tls_request(https_port, "a.test", gw_a_cert)
        expect(alpn is None, f"client ALPN {alpn}")
        expect(fields["alpn"] == "-", fields)

    def terminate_wildcard():
        fields, _, _ = tls_request(https_port, "x.w.test", gw_w_cert)
        expect(fields["sni"] == "x.w.test", fields)

    def passthrough_unknown_host():
        fields, local_port, _ = tls_request(https_port, "b.test", upstream_cert)
        expect(fields["sni"] == "b.test", fields)
        expect(fields["src"] == f"127.0.0.1:{local_port}", fields)

    def passthrough_acme_tls_alpn():
        fields, _, alpn = tls_request(https_port, "a.test", upstream_cert,
                                      ["acme-tls/1"])
        expect(alpn == "acme-tls/1", f"client ALPN {alpn}")
        expect(fields["alpn"] == "acme-tls/1", fields)

    def passthrough_policy():
        fields, _, _ = tls_request(https_port, "grpc.a.test", upstream_cert)
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
            tls_request(https_port, "c.test", gw_c_cert)
            raise AssertionError("c.test was terminated before the reload")
        except ssl.SSLCertVerificationError:
            pass  # Passed through to the upstream certificate, as expected.
        write_atomic(acme_path, acme_json([(*gw_a, "a.test"),
                                           (*gw_w, "*.w.test"),
                                           (*gw_c, "c.test")]))
        deadline = time.monotonic() + 5
        while True:
            try:
                fields, _, _ = tls_request(https_port, "c.test", gw_c_cert)
                expect(fields["sni"] == "c.test", fields)
                return
            except ssl.SSLCertVerificationError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.1)

    def broken_acme_keeps_certificates():
        with open(acme_path, "w") as f:
            f.write('{"le": {"Certificates": [')
        time.sleep(0.6)
        fields, _, _ = tls_request(https_port, "a.test", gw_a_cert)
        expect(fields["sni"] == "a.test", fields)

    def concurrent_connections():
        errors = []

        def one():
            try:
                fields, _, _ = tls_request(https_port, "a.test", gw_a_cert,
                                           ["h2"])
                if fields["got"] != "hello":
                    errors.append(fields)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=one) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        expect(not errors, errors[:3])

    def metrics_exposed():
        body = urllib.request.urlopen(metrics_url + "/metrics",
                                      timeout=2).read().decode()
        values = {}
        for line in body.splitlines():
            if line and not line.startswith("#"):
                key, value = line.rsplit(" ", 1)
                values[key] = float(value)
        terminated = values[
            'bot_shield_routes_total{route="terminate",reason="certificate"}']
        expect(terminated >= 55, f"terminate count {terminated}")
        expect(values['bot_shield_connections_rejected_total'
                      '{reason="not_tls"}'] >= 1, "not_tls count")
        expect(values['bot_shield_connections_rejected_total'
                      '{reason="client_hello_timeout"}'] >= 1, "timeout count")
        expect(values['bot_shield_acme_reloads_total{result="error"}'] >= 1,
               "acme error count")
        expect(values["bot_shield_certificates"] == 3, "certificate gauge")

    for name, fn in [
        ("terminate http/1.1 with PROXY v2", terminate_http11),
        ("terminate h2 keeps ALPN", terminate_h2),
        ("terminate without ALPN", terminate_without_alpn),
        ("terminate wildcard certificate", terminate_wildcard),
        ("passthrough unknown host", passthrough_unknown_host),
        ("passthrough acme-tls/1", passthrough_acme_tls_alpn),
        ("passthrough policy host", passthrough_policy),
        ("plain http passthrough", plain_http_passthrough),
        ("non-TLS rejected", non_tls_rejected),
        ("client hello timeout", client_hello_timeout),
        ("acme.json reload", acme_reload),
        ("broken acme.json keeps certificates", broken_acme_keeps_certificates),
        ("50 concurrent connections", concurrent_connections),
        ("metrics", metrics_exposed),
    ]:
        checks.run(name, fn)

    def graceful_shutdown():
        process.send_signal(signal.SIGTERM)
        code = process.wait(timeout=10)
        expect(code == 0, f"exit code {code}")

    checks.run("graceful shutdown", graceful_shutdown)
    if process.poll() is None:
        process.kill()
    log_file.close()

    if checks.failed:
        print(f"\n{checks.failed} check(s) failed; gateway log:\n")
        print(open(log_path).read()[-4000:])
        sys.exit(1)
    shutil.rmtree(workdir)
    print("\nall e2e checks passed")


if __name__ == "__main__":
    main()
