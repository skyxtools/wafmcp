"""Protocol, parser, live web, TLS, and bounded TCP tests for advanced recon."""
from __future__ import annotations

import datetime
import ipaddress
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import dns.resolver
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from wafmcp.http_client import Probe
from wafmcp.recon import (
    advanced_recon,
    certificate_transparency_names,
    dns_inventory,
    recon_network,
    tcp_service_inventory,
    tls_inventory,
    web_inventory,
)
from wafmcp.rules import Rules
from wafmcp.scope import OutOfScope, Scope


class _Rdata:
    def __init__(self, value: str): self.value = value
    def to_text(self): return self.value


class _Resolver:
    def __init__(self, records): self.records = records
    def resolve(self, name, record_type, lifetime=None):
        key = (str(name).rstrip("."), record_type)
        if key not in self.records:
            raise dns.resolver.NoAnswer
        return [_Rdata(value) for value in self.records[key]]


def _probe(scope_value: str, rules: Rules | None = None) -> Probe:
    scope = Scope()
    scope.configure(scope_value)
    return Probe(scope, rules=rules or Rules())


def test_dns_inventory_collects_infrastructure_mail_controls_and_ptr():
    reverse = "10.2.0.192.in-addr.arpa"
    resolver = _Resolver({
        ("example.test", "A"): ["192.0.2.10"],
        ("example.test", "AAAA"): ["2001:db8::10"],
        ("example.test", "MX"): ["10 mail.example.test."],
        ("example.test", "NS"): ["ns1.example.test."],
        ("example.test", "TXT"): ['"v=spf1 -all"', '"site-verification=x"'],
        ("example.test", "CAA"): ['0 issue "letsencrypt.org"'],
        ("_dmarc.example.test", "TXT"): ['"v=DMARC1; p=reject"'],
        ("_mta-sts.example.test", "TXT"): ['"v=STSv1; id=20260712"'],
        (reverse, "PTR"): ["edge.example.test."],
    })
    result = dns_inventory("example.test", resolver=resolver)
    assert result["records"]["A"] == ["192.0.2.10"]
    assert result["records"]["MX"] == ["10 mail.example.test."]
    assert result["email_security"]["SPF"] == ['"v=spf1 -all"']
    assert result["email_security"]["DMARC"] == ['"v=DMARC1; p=reject"']
    assert result["reverse_dns"]["192.0.2.10"] == ["edge.example.test."]


def test_certificate_transparency_is_bounded_and_filters_unrelated_names():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["q"] == "%.example.test"
        return httpx.Response(200, json=[
            {"name_value": "api.example.test\n*.dev.example.test"},
            {"name_value": "example.test\nexample.test.evil.invalid"},
            {"name_value": "api.example.test"},
        ])

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = certificate_transparency_names(
            "example.test", max_names=2, client=client
        )
    assert result["names"] == ["api.example.test", "dev.example.test"]
    assert result["total_unique"] == 3
    assert result["truncated"]
    assert result["error"] is None


def _serve_web():
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def _send(self, body: str, content_type="text/html", status=200):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("X-Powered-By", "UnitTestFramework")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            seen.append(self.path)
            port = self.server.server_address[1]
            if self.path == "/":
                self._send("""
                <html><head><meta name="generator" content="TestCMS 1.0"></head>
                <body>
                  <a href="/dashboard?tab=profile">dashboard</a>
                  <form action="/checkout" method="post">
                    <input name="quantity"><input type="hidden" name="price">
                  </form>
                  <script src="/static/app.js"></script>
                  <script src="https://cdn.external.invalid/lib.js"></script>
                  <div>/_next/static/chunk.js</div>
                </body></html>
                """)
            elif self.path == "/robots.txt":
                self._send(
                    f"User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: http://127.0.0.1:{port}/extra.xml\n",
                    "text/plain",
                )
            elif self.path == "/sitemap.xml":
                self._send(
                    f"<urlset><url><loc>http://127.0.0.1:{port}/from-map?item=7&amp;view=full</loc></url></urlset>",
                    "application/xml",
                )
            elif self.path == "/extra.xml":
                self._send(
                    f"<sitemapindex><sitemap><loc>http://127.0.0.1:{port}/child.xml</loc></sitemap></sitemapindex>",
                    "application/xml",
                )
            elif self.path == "/child.xml":
                self._send(
                    f"<urlset><url><loc>http://127.0.0.1:{port}/deep/path</loc></url></urlset>",
                    "application/xml",
                )
            elif self.path == "/.well-known/security.txt":
                self._send(
                    f"Contact: mailto:security@example.test\nExpires: 2030-01-01T00:00:00Z\nCanonical: http://127.0.0.1:{port}/.well-known/security.txt\nPolicy: https://example.test/policy\n",
                    "text/plain",
                )
            elif self.path == "/security.txt":
                self._send("not a security file", "text/plain", 404)
            elif self.path == "/static/app.js":
                self._send(
                    'fetch("/api/users?id=7"); axios.post("/api/orders"); '
                    'new WebSocket("wss://socket.example.test/events");\n'
                    '//# sourceMappingURL=app.js.map',
                    "application/javascript",
                )
            else:
                self._send("not found", status=404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return server, seen


def test_web_inventory_maps_standard_files_forms_scripts_and_apis_without_crawling():
    server, seen = _serve_web()
    port = server.server_address[1]
    probe = _probe(f"127.0.0.1:{port}")
    result = web_inventory(
        probe,
        base_url=f"http://127.0.0.1:{port}/",
        request_budget=20,
        max_scripts=5,
        max_sitemaps=4,
    )
    urls = {item["url"]: item for item in result["endpoints"]}
    assert f"http://127.0.0.1:{port}/dashboard" in urls
    assert urls[f"http://127.0.0.1:{port}/dashboard"]["parameters"] == ["tab"]
    assert f"http://127.0.0.1:{port}/admin" in urls
    assert f"http://127.0.0.1:{port}/from-map" in urls
    assert f"http://127.0.0.1:{port}/deep/path" in urls
    assert f"http://127.0.0.1:{port}/api/users" in urls
    assert urls[f"http://127.0.0.1:{port}/api/orders"]["methods"] == ["POST"]
    assert result["forms"][0]["hidden_parameters"] == ["price"]
    assert result["robots"]["note"].startswith("RFC 9309")
    assert result["security_txt"][0]["rfc9116_required_fields_present"]
    assert result["source_map_candidates"] == [f"http://127.0.0.1:{port}/static/app.js.map"]
    assert result["websocket_candidates"] == ["wss://socket.example.test/events"]
    assert any(item["value"] == "Next.js" for item in result["technology_hints"])
    assert any("cdn.external.invalid" in item["url"] for item in result["external_references"])
    assert not any(path.startswith("/api/") for path in seen)
    assert "/static/app.js.map" not in seen
    assert result["confirmed_vulnerabilities"] == []
    probe.close(); server.shutdown()


def test_web_inventory_rejects_soft_404_metadata_and_honors_budget():
    class Handler(BaseHTTPRequestHandler):
        seen = []
        def log_message(self, *args): pass
        def do_GET(self):
            Handler.seen.append(self.path)
            body = b"<html><script src='/app.js'></script>normal page</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    probe = _probe(f"127.0.0.1:{port}")
    result = web_inventory(
        probe, base_url=f"http://127.0.0.1:{port}/", request_budget=5, max_scripts=5
    )
    assert result["robots"] is None
    assert result["security_txt"] == []
    assert result["sitemaps"] == []
    assert result["requests_made"] == 5
    assert result["budget_exhausted"]
    assert "/app.js" not in Handler.seen
    probe.close(); server.shutdown()


class _FakeSocket:
    def __init__(self, banner=b""): self.banner = banner; self.closed = False
    def settimeout(self, value): pass
    def recv(self, size): return self.banner
    def close(self): self.closed = True


def test_tcp_inventory_requires_opt_in_and_separates_observation_from_service_hint():
    calls = []

    def connector(address, timeout):
        calls.append(address)
        if address[1] == 22:
            return _FakeSocket(b"SSH-2.0-OpenSSH_Test\r\n")
        if address[1] == 80:
            raise ConnectionRefusedError
        raise socket.timeout

    probe = _probe("example.test")
    with pytest.raises(ValueError, match="confirm_active_scan"):
        tcp_service_inventory(
            probe, hosts=["example.test"], ports=[22], confirm_active_scan=False,
            connector=connector,
        )
    assert calls == []
    result = tcp_service_inventory(
        probe,
        hosts=["example.test"],
        ports=[22, 80, 443],
        confirm_active_scan=True,
        connector=connector,
    )
    assert result["state_counts"] == {"open": 1, "closed": 1, "filtered_or_unresponsive": 1}
    ssh = result["open_services"][0]
    assert ssh["service_hint_from_port"] == "ssh"
    assert ssh["passive_banner"].startswith("SSH-2.0")
    assert "hint" in ssh["service_note"]
    probe.close()


def test_network_recon_preflights_entire_cidr_before_connecting():
    calls = []
    probe = _probe("192.0.2.0/30")

    def connector(address, timeout):
        calls.append(address)
        return _FakeSocket()

    with pytest.raises(OutOfScope):
        recon_network(
            probe,
            cidr="192.0.3.0/30",
            ports=[22],
            confirm_active_scan=True,
            connector=connector,
        )
    assert calls == []
    with pytest.raises(ValueError, match="usable hosts"):
        recon_network(
            probe,
            cidr="10.0.0.0/8",
            ports=[22],
            max_hosts=256,
            confirm_active_scan=True,
            connector=connector,
        )
    assert calls == []
    result = recon_network(
        probe,
        cidr="192.0.2.0/30",
        ports=[22],
        confirm_active_scan=True,
        connector=connector,
    )
    assert result["active_inventory"]["checks"] == 2
    assert len(result["active_inventory"]["open_services"]) == 2
    assert result["confirmed_vulnerabilities"] == []
    probe.close()


def test_tls_inventory_parses_real_local_certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0)); listener.listen(1)
    port = listener.getsockname()[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    def serve():
        conn, _ = listener.accept()
        try:
            with context.wrap_socket(conn, server_side=True):
                pass
        except (OSError, ssl.SSLError):
            pass
        finally:
            listener.close()

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()
    probe = _probe(f"127.0.0.1:{port}")
    result = tls_inventory(probe, "127.0.0.1", port)
    assert result["observed"]
    assert result["certificate"]["dns_sans"] == ["localhost"]
    assert result["certificate"]["ip_sans"] == ["127.0.0.1"]
    assert result["certificate"]["public_key_type"] == "RSA"
    assert result["certificate"]["public_key_bits"] == 2048
    assert "inventory" in result["certificate"]["trust_note"]
    probe.close()
    server_thread.join(timeout=2)


def test_advanced_recon_combines_passive_layers_without_unrequested_active_scan():
    resolver = _Resolver({("example.test", "A"): ["192.0.2.20"]})

    def ct_handler(request):
        return httpx.Response(200, json=[{"name_value": "api.example.test\nother.invalid"}])

    def fake_tls(probe, host, port, timeout):
        return {
            "observed": True,
            "certificate": {"dns_sans": ["example.test", "api.example.test"]},
        }

    probe = _probe("example.test, *.example.test")
    with httpx.Client(transport=httpx.MockTransport(ct_handler)) as client:
        result = advanced_recon(
            probe,
            target="https://example.test/",
            include_web=False,
            resolver=resolver,
            ct_client=client,
            tls_fetcher=fake_tls,
        )
    assert result["passive"]["dns"]["records"]["A"] == ["192.0.2.20"]
    scoped = result["passive"]["certificate_transparency"]["scoped_names"]
    assert scoped == [{"name": "api.example.test", "in_scope": True}]
    assert result["certificate_name_candidates"][1]["in_scope"]
    assert result["web"] is None
    assert result["active_network"] is None
    assert result["confirmed_vulnerabilities"] == []
    probe.close()
