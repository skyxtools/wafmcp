"""Bounded, evidence-first reconnaissance for authorized engagements.

The module separates passive inventory (DNS and certificate transparency),
low-impact application mapping (TLS/HTTP GET), and explicit active TCP service
discovery. A port-number lookup is only a service hint; observed banners,
certificates, and HTTP responses remain distinct evidence.
"""
from __future__ import annotations

import concurrent.futures
import html
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import timezone
from html.parser import HTMLParser
from typing import Any, Callable
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import dns.exception
import dns.resolver
import dns.reversename
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID

from .http_client import Probe, Response
from .rules import RuleViolation


REFERENCES = {
    "owasp_information_gathering": (
        "https://owasp.org/www-project-web-security-testing-guide/latest/"
        "4-Web_Application_Security_Testing/01-Information_Gathering/README"
    ),
    "owasp_entry_points": (
        "https://owasp.org/www-project-web-security-testing-guide/v42/"
        "4-Web_Application_Security_Testing/01-Information_Gathering/"
        "06-Identify_Application_Entry_Points"
    ),
    "nmap_host_discovery": "https://nmap.org/book/man-host-discovery.html",
    "nmap_service_detection": "https://nmap.org/book/man-version-detection.html",
    "dns_concepts_rfc1034": "https://www.rfc-editor.org/rfc/rfc1034.html",
    "dns_implementation_rfc1035": "https://www.rfc-editor.org/rfc/rfc1035.html",
    "dns_caa_rfc8659": "https://www.rfc-editor.org/rfc/rfc8659.html",
    "portswigger_api_recon": "https://portswigger.net/web-security/api-testing",
    "robots_rfc9309": "https://www.rfc-editor.org/rfc/rfc9309.html",
    "security_txt_rfc9116": "https://www.rfc-editor.org/rfc/rfc9116.html",
    "tls_identity_rfc9525": "https://www.rfc-editor.org/rfc/rfc9525.html",
    "certificate_transparency_rfc9162": "https://www.rfc-editor.org/rfc/rfc9162.html",
    "sitemaps_protocol": "https://www.sitemaps.org/protocol.html",
}

DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "DS", "DNSKEY")
STANDARD_WEB_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
)
STATIC_EXTENSIONS = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".otf", ".mp4", ".webm", ".mp3",
)
SERVICE_HINTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 587: "submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle",
    2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5672: "amqp",
    6379: "redis", 6443: "kubernetes-api", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}
DEFAULT_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433,
                 1521, 2049, 2375, 2376, 3000, 3306, 3389, 5432, 6379, 6443,
                 8080, 8443, 9200, 27017)

_LOC_RE = re.compile(r"(?is)<(?:[a-z0-9_-]+:)?loc>\s*(.*?)\s*</(?:[a-z0-9_-]+:)?loc>")
_SOURCE_MAP_RE = re.compile(r"(?m)[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)")
_JS_URL_RE = re.compile(
    r'''["'`](https?://[^"'`\s<>]+|wss?://[^"'`\s<>]+|(?:\.\.?/|/)[^"'`\s<>]{2,})["'`]'''
)
_FETCH_RE = re.compile(r'''(?i)\bfetch\s*\(\s*["'`]([^"'`]+)["'`]''')
_AXIOS_RE = re.compile(r'''(?i)\baxios\.(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]''')
_XHR_RE = re.compile(r'''(?i)\.open\s*\(\s*["'`](GET|POST|PUT|PATCH|DELETE)["'`]\s*,\s*["'`]([^"'`]+)["'`]''')
def _header(response: Response, name: str) -> str:
    return next(
        (str(value) for key, value in response.headers.items() if key.lower() == name.lower()),
        "",
    )


def _clean_banner(data: bytes) -> str:
    text = data.decode("utf-8", "replace")
    return "".join(char if char.isprintable() else " " for char in text).strip()[:300]


def _is_http_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in {"http", "https"} and bool(parts.hostname)


def _same_origin(url: str, origin: tuple[str, str]) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return (parts.scheme, parts.netloc) == origin


def _host_in_scope(probe: Probe, host: str) -> bool:
    for scheme in ("https", "http"):
        try:
            probe.scope.check(f"{scheme}://{host}/")
            return True
        except Exception:
            continue
    return False


def _target(target: str) -> tuple[str, str]:
    raw = target.strip()
    if not raw:
        raise ValueError("target is required")
    try:
        bare_ip = ipaddress.ip_address(raw)
    except ValueError:
        bare_ip = None
    if bare_ip and bare_ip.version == 6:
        candidate = f"https://[{raw}]/"
    else:
        candidate = raw if "://" in raw else f"https://{raw}"
    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("target must be an HTTP(S) URL, hostname, or IP address")
    if parts.username or parts.password:
        raise ValueError("target URLs containing userinfo are refused")
    base_url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
    return parts.hostname.rstrip(".").lower(), base_url


def _resolver_answer(resolver: Any, name: str, record_type: str) -> list[str]:
    try:
        answer = resolver.resolve(name, record_type, lifetime=2.5)
    except TypeError:
        answer = resolver.resolve(name, record_type)
    values = []
    for item in answer:
        value = item.to_text() if hasattr(item, "to_text") else str(item)
        values.append(value.strip()[:2048])
    return sorted(set(values))[:100]


def dns_inventory(hostname: str, resolver: Any | None = None) -> dict[str, Any]:
    """Collect bounded DNS, mail-security, and reverse-DNS observations."""
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    resolver = resolver or dns.resolver.Resolver()
    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}

    if ip is None:
        for record_type in DNS_TYPES:
            try:
                records[record_type] = _resolver_answer(resolver, hostname, record_type)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                records[record_type] = []
            except (dns.resolver.NoNameservers, dns.exception.Timeout, OSError) as exc:
                records[record_type] = []
                errors[record_type] = type(exc).__name__
        special: dict[str, list[str]] = {}
        for label, name in (
            ("DMARC", f"_dmarc.{hostname}"),
            ("MTA_STS", f"_mta-sts.{hostname}"),
        ):
            try:
                special[label] = _resolver_answer(resolver, name, "TXT")
            except Exception:
                special[label] = []
    else:
        records = {record_type: [] for record_type in DNS_TYPES}
        records[ip.version == 4 and "A" or "AAAA"] = [str(ip)]
        special = {"DMARC": [], "MTA_STS": []}

    ptr: dict[str, list[str]] = {}
    for address in records.get("A", []) + records.get("AAAA", []):
        try:
            reverse = str(dns.reversename.from_address(address))
            ptr[address] = _resolver_answer(resolver, reverse, "PTR")
        except Exception:
            ptr[address] = []
    txt = records.get("TXT", [])
    return {
        "hostname": hostname,
        "records": records,
        "reverse_dns": ptr,
        "email_security": {
            **special,
            "SPF": [value for value in txt if "v=spf1" in value.lower()],
        },
        "lookup_errors": errors,
    }


def certificate_transparency_names(
    domain: str,
    *,
    max_names: int = 200,
    timeout: float = 10.0,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Best-effort passive name inventory from the crt.sh CT search service."""
    if not 1 <= max_names <= 1000:
        raise ValueError("max_ct_names must be between 1 and 1000")
    owned = client is None
    if client is None:
        client = httpx.Client(timeout=timeout, follow_redirects=True)
    names: set[str] = set()
    error = None
    try:
        response = client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
        if response.status_code != 200:
            error = f"crt.sh returned HTTP {response.status_code}"
        else:
            payload = response.json()
            if not isinstance(payload, list):
                raise ValueError("unexpected CT response shape")
            for row in payload:
                if not isinstance(row, dict):
                    continue
                for raw in str(row.get("name_value", "")).splitlines():
                    name = raw.strip().lower().rstrip(".").removeprefix("*.")
                    if name == domain or name.endswith(f".{domain}"):
                        if "@" not in name and len(name) <= 253:
                            names.add(name)
    except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if owned:
            client.close()
    ordered = sorted(names)
    return {
        "source": "crt.sh certificate-transparency search",
        "query_domain": domain,
        "names": ordered[:max_names],
        "total_unique": len(ordered),
        "truncated": len(ordered) > max_names,
        "error": error,
    }


def _cert_time(cert: x509.Certificate, attr: str) -> str:
    value = getattr(cert, f"{attr}_utc", None) or getattr(cert, attr)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def tls_inventory(probe: Probe, hostname: str, port: int, timeout: float = 4.0) -> dict[str, Any]:
    """Observe one TLS endpoint and parse its leaf certificate without asserting trust."""
    url = f"https://{_url_host(hostname)}:{port}/"
    probe.scope.check(url)
    probe.rules.enforce("CONNECT", url)
    probe.rules.throttle()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])
    result: dict[str, Any] = {"host": hostname, "port": port, "observed": False}
    started = time.perf_counter()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=None if _is_ip(hostname) else hostname) as tls:
                der = tls.getpeercert(binary_form=True)
                result.update({
                    "observed": True,
                    "tls_version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "alpn": tls.selected_alpn_protocol(),
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                })
    except (OSError, ssl.SSLError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    if not der:
        result["error"] = "TLS peer did not provide a certificate"
        return result
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        result["error"] = f"certificate parse failed: {exc}"
        return result
    dns_names: list[str] = []
    ip_names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns_names = sorted(set(san.get_values_for_type(x509.DNSName)))[:200]
        ip_names = sorted({str(value) for value in san.get_values_for_type(x509.IPAddress)})[:100]
    except x509.ExtensionNotFound:
        pass
    public_key = cert.public_key()
    key_type = type(public_key).__name__
    key_size = getattr(public_key, "key_size", None)
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type = f"EC/{public_key.curve.name}"
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_type = "DSA"
    result["certificate"] = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_hex": format(cert.serial_number, "x"),
        "not_before": _cert_time(cert, "not_valid_before"),
        "not_after": _cert_time(cert, "not_valid_after"),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "dns_sans": dns_names,
        "ip_sans": ip_names,
        "public_key_type": key_type,
        "public_key_bits": key_size,
        "trust_note": "Leaf certificate observed with verification disabled; this is inventory, not proof of a trusted chain.",
    }
    return result


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _url_host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    return f"[{value}]" if address.version == 6 else value


class _HtmlInventory(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.links: list[tuple[str, str]] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self.generator: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "base" and values.get("href"):
            self.base_href = values["href"]
        if tag == "a" and values.get("href"):
            self.links.append(("link", values["href"]))
        elif tag in {"iframe", "frame"} and values.get("src"):
            self.links.append(("frame", values["src"]))
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        elif tag == "link" and values.get("href"):
            rel = values.get("rel", "").lower()
            if "manifest" in rel:
                self.links.append(("manifest", values["href"]))
        elif tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": values.get("method", "GET").upper(),
                "parameters": [],
                "hidden_parameters": [],
            }
            self.forms.append(self._form)
        elif tag in {"input", "textarea", "select", "button"} and self._form is not None:
            name = values.get("name")
            if name and name not in self._form["parameters"]:
                self._form["parameters"].append(name)
                if tag == "input" and values.get("type", "text").lower() == "hidden":
                    self._form["hidden_parameters"].append(name)
        elif tag == "meta" and values.get("name", "").lower() == "generator":
            self.generator = values.get("content") or None

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None


@dataclass
class _EndpointMap:
    origin: tuple[str, str]
    max_endpoints: int
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    external: dict[str, set[str]] = field(default_factory=dict)

    def add(
        self,
        raw_url: str,
        base_url: str,
        source: str,
        kind: str,
        method: str | None = "GET",
    ) -> None:
        if not raw_url or raw_url.startswith(("javascript:", "data:", "mailto:", "tel:", "#")):
            return
        try:
            url = urljoin(base_url, html.unescape(raw_url.strip()))
            parts = urlsplit(url)
        except ValueError:
            return
        if parts.scheme in {"ws", "wss"}:
            self.external.setdefault(url, set()).add(source)
            return
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return
        if (parts.scheme, parts.netloc) != self.origin:
            self.external.setdefault(url, set()).add(source)
            return
        path_lower = parts.path.lower()
        if path_lower.endswith(STATIC_EXTENSIONS):
            return
        normalized = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
        if normalized not in self.entries and len(self.entries) >= self.max_endpoints:
            return
        entry = self.entries.setdefault(normalized, {
            "url": normalized,
            "methods": set(),
            "parameters": set(),
            "sources": set(),
            "kinds": set(),
            "templated": False,
        })
        if method:
            entry["methods"].add(method.upper())
        entry["parameters"].update(key for key, _ in parse_qsl(parts.query, keep_blank_values=True))
        entry["sources"].add(source)
        entry["kinds"].add(kind)
        entry["templated"] = entry["templated"] or any(token in raw_url for token in ("${", "{{", ":id", "{id}"))

    def output(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        endpoints = []
        for entry in self.entries.values():
            endpoints.append({
                **{key: value for key, value in entry.items() if key not in {"methods", "parameters", "sources", "kinds"}},
                "methods": sorted(entry["methods"]),
                "parameters": sorted(entry["parameters"]),
                "sources": sorted(entry["sources"]),
                "kinds": sorted(entry["kinds"]),
            })
        external = [
            {"url": url, "sources": sorted(sources), "contacted": False}
            for url, sources in self.external.items()
        ]
        return sorted(endpoints, key=lambda item: item["url"]), sorted(external, key=lambda item: item["url"])


def _valid_response(response: Response) -> bool:
    return bool(not response.error and not response.blocked_heuristic and 200 <= response.status < 300)


def _response_observation(name: str, response: Response) -> dict[str, Any]:
    return {
        "name": name,
        "url": response.url,
        "status": response.status,
        "content_type": _header(response, "content-type"),
        "length": response.length,
        "body_sha1": response.body_sha1[:12],
        "blocked_or_error": response.blocked_heuristic or bool(response.error),
    }


def _parse_robots(body: str) -> dict[str, Any] | None:
    directives: list[dict[str, str]] = []
    sitemap_urls: list[str] = []
    current_agents: list[str] = []
    for raw in body[:200_000].splitlines()[:2000]:
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        low = key.lower()
        if low == "user-agent":
            current_agents = [value]
        elif low in {"allow", "disallow"}:
            directives.append({"directive": low, "value": value, "user_agents": current_agents[:]})
        elif low == "sitemap" and value:
            sitemap_urls.append(value)
    if not directives and not sitemap_urls:
        return None
    return {
        "directives": directives[:500],
        "sitemaps": sitemap_urls[:50],
        "note": "RFC 9309 states robots rules are not access authorization; listed paths are inventory only.",
    }


def _parse_sitemap(body: str) -> dict[str, Any] | None:
    sample = body[:200_000]
    low = sample.lower()
    is_index = "<sitemapindex" in low
    if "<urlset" not in low and not is_index:
        return None
    locations = []
    for match in _LOC_RE.findall(sample):
        value = re.sub(r"<[^>]+>", "", html.unescape(match)).strip()
        if _is_http_url(value):
            locations.append(value)
    return {"kind": "sitemap_index" if is_index else "urlset", "locations": list(dict.fromkeys(locations))[:1000]}


def _parse_security_txt(body: str, retrieved_url: str) -> dict[str, Any] | None:
    sample = body[:32768]
    fields: dict[str, list[str]] = {}
    allowed = {"contact", "expires", "encryption", "acknowledgments", "preferred-languages", "canonical", "policy", "hiring"}
    for raw in sample.splitlines()[:1000]:
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.lower() in allowed and len(value.strip()) <= 2048:
            fields.setdefault(key.title(), []).append(value.strip())
    if not fields.get("Contact"):
        return None
    canonical = fields.get("Canonical", [])
    return {
        "retrieved_url": retrieved_url,
        "fields": fields,
        "rfc9116_required_fields_present": bool(fields.get("Contact") and fields.get("Expires")),
        "canonical_matches_retrieval": retrieved_url in canonical if canonical else None,
        "parse_truncated_at_32k": len(body.encode("utf-8", "ignore")) > 32768,
        "note": "RFC 9116 explicitly says security.txt presence does not grant permission to test.",
    }


def _technology_hints(response: Response, body: str, parser: _HtmlInventory) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    for header in ("server", "x-powered-by", "via", "x-generator"):
        value = _header(response, header)
        if value:
            hints.append({"source": f"header:{header}", "value": value[:300]})
    if parser.generator:
        hints.append({"source": "meta:generator", "value": parser.generator[:300]})
    markers = (
        ("Next.js", ("__NEXT_DATA__", "/_next/static/")),
        ("Nuxt", ("__NUXT__", "/_nuxt/")),
        ("WordPress", ("/wp-content/", "/wp-includes/")),
        ("Drupal", ("Drupal.settings", "/sites/default/files/")),
        ("Angular", ("ng-version=", "ng-app=")),
        ("Vite", ("/@vite/", "__vite__")),
        ("Webpack", ("webpackChunk", "__webpack_require__")),
    )
    for name, needles in markers:
        if any(needle in body for needle in needles):
            hints.append({"source": "html_or_bundle_marker", "value": name})
    return hints


def _extract_js(
    body: str,
    script_url: str,
    endpoint_map: _EndpointMap,
    source_maps: set[str],
    websockets: set[str],
) -> None:
    sample = body[:200_000]
    for raw in _JS_URL_RE.findall(sample):
        if raw.startswith(("ws://", "wss://")):
            websockets.add(raw)
        else:
            endpoint_map.add(raw, script_url, f"javascript:{script_url}", "js-string", None)
    for raw in _FETCH_RE.findall(sample):
        endpoint_map.add(raw, script_url, f"javascript:{script_url}", "fetch", "GET")
    for method, raw in _AXIOS_RE.findall(sample):
        endpoint_map.add(raw, script_url, f"javascript:{script_url}", "axios", method)
    for method, raw in _XHR_RE.findall(sample):
        endpoint_map.add(raw, script_url, f"javascript:{script_url}", "xhr", method)
    for raw in _SOURCE_MAP_RE.findall(sample):
        try:
            source_maps.add(urljoin(script_url, raw.strip().strip("'\"")))
        except ValueError:
            continue


def web_inventory(
    probe: Probe,
    *,
    base_url: str,
    identity_headers: dict[str, str] | None = None,
    request_budget: int = 20,
    max_scripts: int = 8,
    max_sitemaps: int = 4,
    max_endpoints: int = 1000,
) -> dict[str, Any]:
    """Perform bounded same-origin GET reconnaissance without recursive crawling."""
    if not 5 <= request_budget <= 50:
        raise ValueError("request_budget must be between 5 and 50")
    if not 0 <= max_scripts <= 20:
        raise ValueError("max_scripts must be between 0 and 20")
    if not 1 <= max_sitemaps <= 10:
        raise ValueError("max_sitemaps must be between 1 and 10")
    if not 100 <= max_endpoints <= 5000:
        raise ValueError("max_endpoints must be between 100 and 5000")
    parts = urlsplit(base_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("base_url must be HTTP(S)")
    origin = (parts.scheme, parts.netloc)
    root = f"{parts.scheme}://{parts.netloc}/"
    endpoint_map = _EndpointMap(origin, max_endpoints)
    observations: list[dict[str, Any]] = []
    cache: dict[str, Response] = {}
    skipped: set[str] = set()
    headers = dict(identity_headers or {})

    def get(name: str, url: str) -> Response | None:
        if url in cache:
            return cache[url]
        if url in skipped:
            return None
        if len(cache) >= request_budget:
            return None
        if not _same_origin(url, origin):
            return None
        try:
            probe.rules.enforce("GET", url)
        except RuleViolation as exc:
            skipped.add(url)
            observations.append({
                "name": name,
                "url": url,
                "skipped_by_program_rules": str(exc),
            })
            return None
        response = probe.send("GET", url, headers=headers)
        cache[url] = response
        observations.append(_response_observation(name, response))
        return response

    base_response = get("base_document", base_url)
    standard: dict[str, Response | None] = {}
    for path in STANDARD_WEB_PATHS:
        standard[path] = get(path, urljoin(root, path))

    parser = _HtmlInventory()
    technology: list[dict[str, str]] = []
    scripts: list[str] = []
    forms: list[dict[str, Any]] = []
    if base_response and _valid_response(base_response):
        body = base_response.body_text
        parser.feed(body)
        document_base = urljoin(base_url, parser.base_href or "")
        endpoint_map.add(base_url, base_url, "base_document", "document")
        for kind, raw in parser.links:
            endpoint_map.add(raw, document_base, "html", kind)
        for form in parser.forms:
            action = urljoin(document_base, form["action"] or base_url)
            endpoint_map.add(action, document_base, "html_form", "form", form["method"])
            forms.append({**form, "action": action})
        for raw in parser.scripts:
            url = urljoin(document_base, raw)
            if _same_origin(url, origin):
                scripts.append(url)
            else:
                endpoint_map.external.setdefault(url, set()).add("html_script")
        technology.extend(_technology_hints(base_response, body, parser))

    robots = None
    sitemap_queue: list[str] = [urljoin(root, "/sitemap.xml")]
    robots_response = standard["/robots.txt"]
    if robots_response and _valid_response(robots_response):
        robots = _parse_robots(robots_response.body_text)
        if robots:
            for directive in robots["directives"]:
                value = directive["value"]
                if value:
                    endpoint_map.add(value, root, "robots.txt", directive["directive"])
            for raw in robots["sitemaps"]:
                url = urljoin(root, raw)
                if _same_origin(url, origin):
                    sitemap_queue.append(url)
                else:
                    endpoint_map.external.setdefault(url, set()).add("robots_sitemap")

    security_files = []
    for path in ("/.well-known/security.txt", "/security.txt"):
        response = standard[path]
        if response and _valid_response(response):
            parsed = _parse_security_txt(response.body_text, urljoin(root, path))
            if parsed:
                security_files.append(parsed)

    sitemaps: list[dict[str, Any]] = []
    visited_sitemaps: set[str] = set()
    while sitemap_queue and len(visited_sitemaps) < max_sitemaps:
        url = sitemap_queue.pop(0)
        if url in visited_sitemaps or not _same_origin(url, origin):
            continue
        visited_sitemaps.add(url)
        response = cache.get(url) or get("sitemap", url)
        if not response or not _valid_response(response):
            continue
        parsed = _parse_sitemap(response.body_text)
        if not parsed:
            continue
        in_scope_locations = 0
        external_locations = 0
        for location in parsed["locations"]:
            if _same_origin(location, origin):
                in_scope_locations += 1
                if parsed["kind"] == "sitemap_index":
                    sitemap_queue.append(location)
                else:
                    endpoint_map.add(location, root, f"sitemap:{url}", "sitemap")
            else:
                external_locations += 1
                endpoint_map.external.setdefault(location, set()).add(f"sitemap:{url}")
        sitemaps.append({
            "url": url,
            "kind": parsed["kind"],
            "locations": len(parsed["locations"]),
            "same_origin_locations": in_scope_locations,
            "external_locations": external_locations,
        })

    source_maps: set[str] = set()
    websockets: set[str] = set()
    fetched_scripts: list[dict[str, Any]] = []
    for script_url in list(dict.fromkeys(scripts))[:max_scripts]:
        response = get("javascript", script_url)
        if not response or not _valid_response(response):
            continue
        _extract_js(response.body_text, script_url, endpoint_map, source_maps, websockets)
        fetched_scripts.append({
            "url": script_url,
            "status": response.status,
            "length": response.length,
            "body_sha1": response.body_sha1[:12],
        })

    endpoints, external = endpoint_map.output()
    api_candidates = [
        item for item in endpoints
        if re.search(r"(?:/api(?:/|$)|/graphql(?:/|$)|/rest(?:/|$)|\.json$)", urlsplit(item["url"]).path, re.I)
    ]
    parameter_names = sorted({name for item in endpoints for name in item["parameters"]})
    return {
        "base_url": base_url,
        "request_budget": request_budget,
        "requests_made": len(cache),
        "requests_skipped_by_program_rules": len(skipped),
        "budget_exhausted": len(cache) >= request_budget,
        "observations": observations,
        "technology_hints": technology,
        "robots": robots,
        "security_txt": security_files,
        "sitemaps": sitemaps,
        "forms": forms,
        "scripts": fetched_scripts,
        "source_map_candidates": sorted(source_maps),
        "websocket_candidates": sorted(websockets),
        "endpoints": endpoints,
        "api_candidates": api_candidates,
        "parameter_names": parameter_names,
        "external_references": external,
        "confirmed_vulnerabilities": [],
        "note": "Only the base document, standard metadata files, bounded same-origin sitemaps, and bounded same-origin scripts were fetched; discovered application endpoints were not crawled.",
    }


Connector = Callable[[tuple[str, int], float], Any]


def _connect(address: tuple[str, int], timeout: float) -> socket.socket:
    return socket.create_connection(address, timeout=timeout)


def _tcp_one(
    probe: Probe,
    host: str,
    port: int,
    timeout: float,
    connector: Connector,
) -> dict[str, Any]:
    probe.rules.throttle()
    started = time.perf_counter()
    try:
        sock = connector((host, port), timeout)
    except ConnectionRefusedError:
        return {"host": host, "port": port, "state": "closed", "reason": "connection_refused"}
    except (socket.timeout, TimeoutError):
        return {"host": host, "port": port, "state": "filtered_or_unresponsive", "reason": "timeout"}
    except OSError as exc:
        return {"host": host, "port": port, "state": "unreachable_or_error", "reason": type(exc).__name__}
    banner = ""
    try:
        sock.settimeout(min(timeout, 0.35))
        try:
            banner = _clean_banner(sock.recv(512))
        except (socket.timeout, TimeoutError, OSError):
            pass
    finally:
        sock.close()
    return {
        "host": host,
        "port": port,
        "state": "open",
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "service_hint_from_port": SERVICE_HINTS.get(port, "unknown"),
        "passive_banner": banner or None,
        "service_note": "Port mapping is only a hint; no active version probe was sent.",
    }


def tcp_service_inventory(
    probe: Probe,
    *,
    hosts: list[str],
    ports: list[int],
    confirm_active_scan: bool,
    timeout: float = 0.8,
    max_workers: int = 20,
    connector: Connector = _connect,
) -> dict[str, Any]:
    """Bounded TCP connect inventory with no application-level probes."""
    if not confirm_active_scan:
        raise ValueError("confirm_active_scan=true is required before TCP service discovery")
    unique_hosts = list(dict.fromkeys(hosts))
    unique_ports = sorted(set(ports))
    if not unique_hosts or len(unique_hosts) > 256:
        raise ValueError("hosts must contain between 1 and 256 entries")
    if not unique_ports or len(unique_ports) > 100:
        raise ValueError("ports must contain between 1 and 100 entries")
    if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in unique_ports):
        raise ValueError("every port must be an integer between 1 and 65535")
    if len(unique_hosts) * len(unique_ports) > 4096:
        raise ValueError("active network inventory is capped at 4096 host-port checks")
    if not 0.1 <= timeout <= 5.0:
        raise ValueError("port timeout must be between 0.1 and 5 seconds")

    checks = []
    for host in unique_hosts:
        for port in unique_ports:
            url = f"tcp://{_url_host(host)}:{port}/"
            probe.scope.check(url)
            probe.rules.enforce("CONNECT", url)
            checks.append((host, port))
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(checks))) as executor:
        futures = [executor.submit(_tcp_one, probe, host, port, timeout, connector) for host, port in checks]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    counts: dict[str, int] = {}
    for item in results:
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    return {
        "hosts": unique_hosts,
        "ports": unique_ports,
        "checks": len(checks),
        "state_counts": counts,
        "open_services": sorted(
            (item for item in results if item["state"] == "open"),
            key=lambda item: (item["host"], item["port"]),
        ),
        "non_open_summary_only": True,
        "method": "TCP connect plus passive server-first banner read; no version payloads sent",
    }


def recon_network(
    probe: Probe,
    *,
    cidr: str,
    ports: list[int] | None = None,
    max_hosts: int = 256,
    confirm_active_scan: bool = False,
    timeout: float = 0.8,
    connector: Connector = _connect,
) -> dict[str, Any]:
    """Inventory a bounded in-scope IP network using explicit TCP connect checks."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR: {exc}") from exc
    if not 1 <= max_hosts <= 256:
        raise ValueError("max_hosts must be between 1 and 256")
    usable_hosts = network.num_addresses
    if network.version == 4 and network.prefixlen < 31:
        usable_hosts = max(0, usable_hosts - 2)
    if usable_hosts > max_hosts:
        raise ValueError(f"CIDR contains {usable_hosts} usable hosts; max_hosts is {max_hosts}")
    hosts = [str(address) for address in network.hosts()]
    if not hosts and network.num_addresses == 1:
        hosts = [str(network.network_address)]
    result = tcp_service_inventory(
        probe,
        hosts=hosts,
        ports=list(ports or DEFAULT_PORTS),
        confirm_active_scan=confirm_active_scan,
        timeout=timeout,
        connector=connector,
    )
    return {
        "references": REFERENCES,
        "target_cidr": str(network),
        "active_inventory": result,
        "confirmed_vulnerabilities": [],
        "note": "An open port is an inventory fact, not a vulnerability. Service names based only on port numbers remain hints.",
    }


def advanced_recon(
    probe: Probe,
    *,
    target: str,
    identity_headers: dict[str, str] | None = None,
    use_ct: bool = True,
    max_ct_names: int = 200,
    include_web: bool = True,
    request_budget: int = 20,
    max_scripts: int = 8,
    active_ports: list[int] | None = None,
    confirm_active_scan: bool = False,
    port_timeout: float = 0.8,
    resolver: Any | None = None,
    ct_client: httpx.Client | None = None,
    tls_fetcher: Callable[[Probe, str, int, float], dict[str, Any]] = tls_inventory,
    connector: Connector = _connect,
) -> dict[str, Any]:
    """Combine passive host intelligence with bounded web and opt-in TCP mapping."""
    hostname, base_url = _target(target)
    probe.scope.check(base_url)
    dns_result = dns_inventory(hostname, resolver=resolver)
    ct_result: dict[str, Any] = {"enabled": False, "names": []}
    if use_ct and not _is_ip(hostname):
        ct_result = certificate_transparency_names(
            hostname, max_names=max_ct_names, client=ct_client
        )
        ct_result["enabled"] = True
        ct_result["scoped_names"] = [
            {"name": name, "in_scope": _host_in_scope(probe, name)}
            for name in ct_result["names"]
        ]

    tls_result = None
    parts = urlsplit(base_url)
    if parts.scheme == "https":
        tls_result = tls_fetcher(probe, hostname, parts.port or 443, 4.0)

    web_result = None
    if include_web:
        web_result = web_inventory(
            probe,
            base_url=base_url,
            identity_headers=identity_headers,
            request_budget=request_budget,
            max_scripts=max_scripts,
        )

    active_result = None
    if active_ports:
        active_result = tcp_service_inventory(
            probe,
            hosts=[hostname],
            ports=active_ports,
            confirm_active_scan=confirm_active_scan,
            timeout=port_timeout,
            connector=connector,
        )
    elif confirm_active_scan:
        active_result = tcp_service_inventory(
            probe,
            hosts=[hostname],
            ports=list(DEFAULT_PORTS),
            confirm_active_scan=True,
            timeout=port_timeout,
            connector=connector,
        )

    san_candidates = []
    if tls_result and isinstance(tls_result.get("certificate"), dict):
        for name in tls_result["certificate"].get("dns_sans", []):
            clean = name.removeprefix("*.").lower()
            san_candidates.append({"name": name, "in_scope": _host_in_scope(probe, clean)})
    return {
        "references": REFERENCES,
        "target": {"input": target, "hostname": hostname, "base_url": base_url},
        "passive": {
            "dns": dns_result,
            "certificate_transparency": ct_result,
        },
        "tls": tls_result,
        "certificate_name_candidates": san_candidates,
        "web": web_result,
        "active_network": active_result,
        "confirmed_vulnerabilities": [],
        "next_steps": [
            "Validate scope for every discovered hostname before contacting it; CT, DNS, SAN, robots, and sitemap entries are inventory, not authorization.",
            "Use wayback_urls for historical passive URL coverage, then audit_api/analyze_openapi and audit_graphql only on concrete in-scope candidates.",
            "Treat technology markers and port service names as hypotheses until multiple observations or a bounded service probe confirms them.",
        ],
    }
