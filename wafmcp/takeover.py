"""Subdomain takeover detection - dangling CNAME to an unclaimed service.

When a subdomain has a CNAME to a third-party service (GitHub Pages, S3, Heroku,
etc.) but that resource was never claimed or was deleted, an attacker can claim
it and serve content on the victim's subdomain. Often Critical (cookie scope,
OAuth redirects, phishing on a trusted domain), deterministic, and purely passive
to detect.

Evidence-first: a CNAME alone is NOT a finding. We confirm only when
  1. the subdomain CNAMEs to a fingerprinted service, AND
  2. fetching it returns that service's known "unclaimed / no such site" body.

Signatures adapted from the community can-i-take-over-xyz project (deduplicated
to high-confidence fingerprints).
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Any

from .http_client import Probe, Response

# service -> (cname substring markers, body/claim-error fingerprints)
# A finding requires BOTH a cname match and a fingerprint match, except for a few
# services whose fingerprint alone is unambiguous.
_SERVICES: list[dict[str, Any]] = [
    {
        "service": "GitHub Pages",
        "cname": ["github.io"],
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"],
    },
    {
        "service": "AWS S3 bucket",
        "cname": ["s3.amazonaws.com", "s3-website", ".s3.", "amazonaws.com"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    {
        "service": "Heroku",
        "cname": ["herokuapp.com", "herokudns.com", "herokussl.com"],
        "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    },
    {
        "service": "Fastly",
        "cname": ["fastly.net"],
        "fingerprints": ["Fastly error: unknown domain"],
    },
    {
        "service": "Shopify",
        "cname": ["myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left!"],
    },
    {
        "service": "Surge.sh",
        "cname": ["surge.sh"],
        "fingerprints": ["project not found"],
    },
    {
        "service": "Bitbucket",
        "cname": ["bitbucket.io"],
        "fingerprints": ["Repository not found"],
    },
    {
        "service": "Ghost",
        "cname": ["ghost.io"],
        "fingerprints": ["The thing you were looking for is no longer here", "domain error"],
    },
    {
        "service": "Pantheon",
        "cname": ["pantheonsite.io"],
        "fingerprints": ["The gods are wise, but do not know of the site which you seek"],
    },
    {
        "service": "Tumblr",
        "cname": ["domains.tumblr.com"],
        "fingerprints": ["Whatever you were looking for doesn't currently exist at this address"],
    },
    {
        "service": "Wordpress",
        "cname": ["wordpress.com"],
        "fingerprints": ["Do you want to register"],
    },
    {
        "service": "Cargo",
        "cname": ["cargocollective.com"],
        "fingerprints": ["404 Not Found", "If you're moving your domain away from Cargo"],
    },
    {
        "service": "Azure",
        "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net"],
        "fingerprints": ["404 Web Site not found"],
    },
    {
        "service": "Readthedocs",
        "cname": ["readthedocs.io"],
        "fingerprints": ["unknown to Read the Docs"],
    },
    {
        "service": "Netlify",
        "cname": ["netlify.app", "netlify.com"],
        "fingerprints": ["Not Found - Request ID"],
    },
]


@dataclass
class TakeoverResult:
    host: str
    cname_chain: list[str] = field(default_factory=list)
    service: str | None = None
    confirmed: bool = False
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "cname_chain": self.cname_chain,
            "service": self.service,
            "confirmed": self.confirmed,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "next_steps": self._next_steps(),
        }

    def _next_steps(self) -> list[str]:
        if self.confirmed:
            return [
                f"1. CONFIRMED dangling CNAME to {self.service}. The subdomain "
                f"{self.host} points at an UNCLAIMED {self.service} resource.",
                f"2. PoC: register/claim the resource on {self.service} using the "
                "target name in the CNAME, then serve a benign proof file (e.g. a "
                "text file with your handle + timestamp). Do NOT serve malicious content.",
                "3. Report as subdomain takeover; impact = attacker-controlled content "
                "on a trusted subdomain (cookie theft, OAuth redirect abuse, phishing).",
                "4. Include the CNAME chain and the claim-error body as evidence.",
            ]
        if self.service and self.cname_chain:
            return [
                f"CNAME points to {self.service} but the unclaimed-fingerprint was not "
                "matched - the resource is likely still claimed/active. Not a takeover. "
                "Re-check if the service is later decommissioned.",
            ]
        return ["No dangling CNAME to a known takeover-prone service detected."]


def resolve_cname_chain(host: str) -> list[str]:
    """Return the CNAME chain for host (best-effort, never raises).

    Uses dnspython if available for true CNAME records; falls back to the
    canonical name from the system resolver.
    """
    chain: list[str] = []
    try:
        import dns.resolver  # type: ignore

        name = host
        for _ in range(10):
            try:
                ans = dns.resolver.resolve(name, "CNAME")
            except Exception:
                break
            target = str(ans[0].target).rstrip(".")
            if not target or target == name:
                break
            chain.append(target)
            name = target
        return chain
    except ImportError:
        pass
    # fallback: canonical name via getaddrinfo
    try:
        canon = socket.getaddrinfo(host, None, flags=socket.AI_CANONNAME)
        cn = canon[0][3] if canon and canon[0][3] else ""
        if cn and cn.rstrip(".") != host:
            chain.append(cn.rstrip("."))
    except socket.gaierror:
        pass
    return chain


def _match_service(cname_chain: list[str]) -> dict[str, Any] | None:
    hay = " ".join(cname_chain).lower()
    for svc in _SERVICES:
        if any(marker in hay for marker in svc["cname"]):
            return svc
    return None


def check_takeover(probe: Probe, host: str, scheme: str = "https") -> TakeoverResult:
    res = TakeoverResult(host=host)
    res.cname_chain = resolve_cname_chain(host)
    if res.cname_chain:
        res.evidence.append(f"CNAME chain: {' -> '.join(res.cname_chain)}")
    else:
        res.evidence.append("no CNAME chain (A record or unresolvable) - takeover unlikely")

    svc = _match_service(res.cname_chain)
    if not svc:
        res.evidence.append("CNAME does not point to a known takeover-prone service")
        return res
    res.service = svc["service"]
    res.evidence.append(f"CNAME points to takeover-prone service: {svc['service']}")

    # fetch and look for the unclaimed fingerprint
    try:
        r: Response = probe.send("GET", f"{scheme}://{host}/")
    except Exception as e:
        res.evidence.append(f"fetch failed ({type(e).__name__}: {e})")
        return res
    body = (r.body_text or r.body_snippet or "")
    res.evidence.append(f"fetched {host}: status={r.status} len={r.length}")
    for fp in svc["fingerprints"]:
        if fp.lower() in body.lower():
            res.confirmed = True
            res.confidence = 0.95
            res.evidence.append(f"matched unclaimed-fingerprint: {fp!r} -> TAKEOVER")
            return res
    res.evidence.append("no unclaimed-fingerprint matched -> resource still claimed (not a takeover)")
    res.confidence = 0.2
    return res
