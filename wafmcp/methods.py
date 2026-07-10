"""HTTP method audit - which dangerous methods does the app accept?

Sends OPTIONS to read Allow, then probes each method individually (some servers
don't reflect them in Allow). Also tests method-override headers, a common
bypass: some frameworks route based on X-HTTP-Method-Override even when the
outer method is GET, letting an attacker smuggle DELETE past a WAF that only
inspects the outer verb.

A method is "accepted" when it does not return 405 / 501 and doesn't look like
a WAF block. A method being accepted is not itself a finding - the LLM has to
judge intent (e.g. anonymous PUT on /users/1 is Critical, but on /upload it may
be by design). The oracle here surfaces the surface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .http_client import Probe

_DANGEROUS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
]


@dataclass
class MethodAudit:
    url: str
    allow_header: str = ""
    accepted: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    override_bypasses: list[dict[str, Any]] = field(default_factory=list)
    trace_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "allow_header": self.allow_header,
            "accepted_methods": self.accepted,
            "rejected_methods": self.rejected,
            "method_override_bypass": self.override_bypasses,
            "trace_enabled": self.trace_enabled,
            "next_steps": self._next_steps(),
        }

    def _next_steps(self) -> list[str]:
        steps: list[str] = []
        dangerous_ok = [a for a in self.accepted if a["method"] in _DANGEROUS]
        if dangerous_ok:
            steps.append(
                f"Server accepts {[a['method'] for a in dangerous_ok]} on {self.url}. "
                "For each, test as anonymous AND as a low-privileged identity: can they "
                "modify or delete resources they don't own? That's the finding."
            )
        if self.override_bypasses:
            steps.append(
                f"Method-override bypass detected: {self.override_bypasses}. A GET "
                "smuggling DELETE via {header} lands - can bypass WAFs or route-level "
                "auth that only inspects the outer verb.".format(
                    header=self.override_bypasses[0]["header"]
                )
            )
        if self.trace_enabled:
            steps.append(
                "TRACE is enabled - historically enables XST when combined with a "
                "cross-domain script include. Modern browsers block this, but note it."
            )
        if not steps:
            steps.append("No dangerous methods or override bypasses accepted.")
        return steps


def _accepted(status: int) -> bool:
    return status not in (0, 405, 501) and status < 500


def audit_methods(probe: Probe, url: str) -> MethodAudit:
    res = MethodAudit(url=url)

    # OPTIONS baseline
    r_opt = probe.send("OPTIONS", url)
    res.allow_header = r_opt.headers.get("allow") or r_opt.headers.get("Allow", "")

    for m in ["GET", "POST"] + _DANGEROUS:
        r = probe.send(m, url)
        entry = {"method": m, "status": r.status, "length": r.length}
        (res.accepted if _accepted(r.status) else res.rejected).append(entry)
        if m == "TRACE" and r.status == 200 and "TRACE" in (r.body_text or "").upper():
            res.trace_enabled = True

    # method-override: GET carrying a header that asks for DELETE
    # confirm bypass by comparing to direct DELETE status
    direct_delete = next((a["status"] for a in res.accepted + res.rejected
                          if a["method"] == "DELETE"), None)
    for hdr in _OVERRIDE_HEADERS:
        for target in ("DELETE", "PUT"):
            r = probe.send("GET", url, headers={hdr: target})
            if _accepted(r.status) and (direct_delete in (405, 501, None)
                                        or (direct_delete and r.status != direct_delete)):
                res.override_bypasses.append({
                    "header": hdr, "override_to": target,
                    "status": r.status, "direct_status": direct_delete,
                })

    return res
