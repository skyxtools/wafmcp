"""Origin IP discovery - route around the WAF to test the real backend.

A WAF/CDN in front of the app is interference (see waf.py). If the program
authorizes it, reaching the *origin* server directly lets you test the backend
without the WAF distorting results - payloads that were 'blocked' through the CDN
may land directly.

This module is evidence-first: a DNS record is only a CANDIDATE. An origin is
CONFIRMED only when connecting straight to the candidate IP with the target's
Host header returns the same site as the through-CDN baseline. That direct
connection touches the candidate IP, so it is scope-gated like everything else.

Candidate sources (passive OSINT about the domain, not attacks on the target):
  - crt.sh certificate-transparency logs  -> subdomains
  - resolution of common leaky subdomains (direct, origin, dev, mail, ...)
CDN-owned IPs are excluded up front (an IP inside Cloudflare's range is the CDN,
not the origin).
"""
from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

import httpx

from .http_client import Probe, Response

# Well-known CDN/WAF IPv4 ranges. An address here is the edge, never the origin.
_CDN_RANGES = [
    # Cloudflare
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16",
    # Akamai (partial, common)
    "23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10",
]
_CDN_NETS = [ipaddress.ip_network(c) for c in _CDN_RANGES]

# Subdomains that frequently point straight at the origin, bypassing the CDN.
_LEAKY_SUBDOMAINS = [
    "origin", "direct", "direct-connect", "cpanel", "webmail", "mail", "smtp",
    "ftp", "dev", "staging", "stage", "test", "api", "admin", "portal",
    "vpn", "remote", "server", "host", "backend", "old", "legacy", "beta",
]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def is_cdn_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CDN_NETS)


def _title(body: str) -> str:
    m = _TITLE_RE.search(body or "")
    return " ".join(m.group(1).split())[:120] if m else ""


@dataclass
class OriginCandidate:
    ip: str
    sources: list[str] = field(default_factory=list)          # how we found it
    confirmed: bool = False
    in_scope: bool = True
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "sources": self.sources,
            "confirmed": self.confirmed,
            "in_scope": self.in_scope,
            "evidence": self.evidence,
        }


def _resolve(name: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(name, None, family=socket.AF_INET)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    except Exception:
        return []
    return sorted({i[4][0] for i in infos})


def _crtsh_subdomains(hostname: str, timeout: float = 8.0) -> set[str]:
    """Best-effort certificate-transparency lookup. Never raises, never hangs
    long (short timeout so the tool stays responsive)."""
    root = hostname.lstrip("*.")
    subs: set[str] = set()
    try:
        r = httpx.get(
            "https://crt.sh/", params={"q": f"%.{root}", "output": "json"},
            timeout=timeout, follow_redirects=True,
        )
        if r.status_code == 200:
            for row in r.json():
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(root) and "@" not in name:
                        subs.add(name)
    except Exception:
        pass
    return subs


def gather_candidates(
    hostname: str, use_crtsh: bool = True, max_names: int = 150
) -> dict[str, OriginCandidate]:
    """Collect candidate origin IPs from CT logs + subdomain resolution, minus
    any CDN-owned address. Purely passive: queries public DNS/CT, not the target.

    Resolution is parallelized and the candidate name set is capped (max_names)
    so a domain with hundreds of CT entries can't stall the tool."""
    root = hostname.lstrip("*.")
    names = {root} | {f"{s}.{root}" for s in _LEAKY_SUBDOMAINS}
    if use_crtsh:
        names |= _crtsh_subdomains(root)

    # cap: always keep apex + leaky subdomains, then fill from CT up to the limit
    priority = {root} | {f"{s}.{root}" for s in _LEAKY_SUBDOMAINS}
    ordered = sorted(priority & names) + sorted(names - priority)
    ordered = ordered[:max_names]

    candidates: dict[str, OriginCandidate] = {}
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_resolve, name): name for name in ordered}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                ips = fut.result()
            except Exception:
                continue
            for ip in ips:
                if is_cdn_ip(ip):
                    continue
                c = candidates.setdefault(ip, OriginCandidate(ip=ip))
                label = "apex" if name == root else name
                if label not in c.sources:
                    c.sources.append(label)
    return candidates


def validate_origin(
    probe: Probe, hostname: str, candidate: OriginCandidate, baseline: Response,
    scheme: str = "http",
) -> OriginCandidate:
    """Confirm a candidate by connecting straight to its IP with the target's
    Host header and comparing to the through-CDN baseline. The direct request is
    scope-checked by Probe.send (candidate IP must be in scope)."""
    base_title = _title(baseline.body_text or baseline.body_snippet)
    try:
        r = probe.send(
            "GET", f"{scheme}://{candidate.ip}/", headers={"Host": hostname}
        )
    except Exception as e:  # OutOfScope / RuleViolation bubble up as messages
        candidate.in_scope = "OutOfScope" not in type(e).__name__
        candidate.evidence.append(f"direct connect refused: {type(e).__name__}: {e}")
        return candidate

    direct_title = _title(r.body_text or r.body_snippet)
    candidate.evidence.append(
        f"direct {candidate.ip}: status={r.status} len={r.length} title={direct_title!r}"
    )
    candidate.evidence.append(
        f"baseline: status={baseline.status} len={baseline.length} title={base_title!r}"
    )
    exact = r.body_sha1 == baseline.body_sha1 and r.status == baseline.status
    title_match = bool(base_title) and direct_title == base_title
    len_close = baseline.length and abs(r.length - baseline.length) <= max(
        256, 0.1 * baseline.length
    )
    confirmed = exact or (title_match and len_close) or (title_match and r.status == baseline.status)
    if confirmed:
        why = "identical body" if exact else "matching <title> + similar length"
        candidate.evidence.append(f"CONFIRMED origin ({why}) - backend reachable without the WAF")
    candidate.confirmed = confirmed
    return candidate
