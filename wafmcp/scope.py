"""Scope enforcement - default-deny allowlist.

Every outbound request MUST pass through `Scope.check()`. This is the single
guardrail that keeps an authorized engagement authorized: no host outside the
allowlist is ever contacted, no matter what the LLM proposes.

Allowlist is loaded from WAFMCP_SCOPE (comma-separated) or a scope file passed
at startup. Entries may be:
  - exact host:        api.example.com
  - wildcard subdomain: *.example.com   (matches a.example.com, not example.com)
  - CIDR:              10.0.0.0/24
  - host:port:         example.com:8443  (restricts to that port)
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit


class OutOfScope(Exception):
    """Raised when a target is not covered by the allowlist."""


@dataclass
class ScopeRule:
    raw: str
    host: str | None = None
    wildcard: str | None = None          # ".example.com" suffix form
    network: ipaddress._BaseNetwork | None = None
    port: int | None = None

    @classmethod
    def parse(cls, raw: str) -> "ScopeRule":
        raw = raw.strip()
        host_part, _, port_part = raw.rpartition(":")
        port = None
        # rpartition on "1.2.3.4/24" or "*.x.com" would misfire, so only treat
        # trailing ":<int>" as a port.
        if host_part and port_part.isdigit():
            port = int(port_part)
            raw_host = host_part
        else:
            raw_host = raw

        # CIDR / bare IP
        try:
            net = ipaddress.ip_network(raw_host, strict=False)
            return cls(raw=raw, network=net, port=port)
        except ValueError:
            pass

        if raw_host.startswith("*."):
            return cls(raw=raw, wildcard=raw_host[1:].lower(), port=port)  # ".example.com"
        return cls(raw=raw, host=raw_host.lower(), port=port)

    def matches(self, host: str, port: int) -> bool:
        host = host.lower()
        if self.port is not None and self.port != port:
            return False
        if self.network is not None:
            try:
                return ipaddress.ip_address(host) in self.network
            except ValueError:
                return False
        if self.wildcard is not None:
            return host.endswith(self.wildcard) and host != self.wildcard[1:]
        return self.host == host


def _split(raw: str) -> list[str]:
    """Split a comma/newline separated spec, dropping blanks and # comments."""
    if raw and os.path.isfile(raw):
        with open(raw, "r", encoding="utf-8") as fh:
            raw = ",".join(
                line.strip() for line in fh if line.strip() and not line.startswith("#")
            )
    out: list[str] = []
    for chunk in raw.replace("\n", ",").split(","):
        c = chunk.strip()
        if c and not c.startswith("#"):
            out.append(c)
    return out


@dataclass
class Scope:
    rules: list[ScopeRule] = field(default_factory=list)       # in-scope (allow)
    deny: list[ScopeRule] = field(default_factory=list)        # out-of-scope (deny, wins)

    @classmethod
    def load(cls, spec: str | None = None, deny_spec: str | None = None) -> "Scope":
        allow_raw = spec if spec is not None else os.environ.get("WAFMCP_SCOPE", "")
        deny_raw = deny_spec if deny_spec is not None else os.environ.get("WAFMCP_OUT_OF_SCOPE", "")
        return cls(
            rules=[ScopeRule.parse(r) for r in _split(allow_raw)],
            deny=[ScopeRule.parse(r) for r in _split(deny_raw)],
        )

    def configure(self, in_scope: str, out_of_scope: str = "") -> None:
        """Set the allow/deny lists at runtime (used by the set_scope tool)."""
        self.rules = [ScopeRule.parse(r) for r in _split(in_scope)]
        self.deny = [ScopeRule.parse(r) for r in _split(out_of_scope)]

    @property
    def configured(self) -> bool:
        return bool(self.rules)

    def check(self, url: str) -> tuple[str, int]:
        """Return (host, port) if in scope, else raise OutOfScope.

        Deny rules ALWAYS win: an out-of-scope match is rejected even if an
        in-scope rule also matches. This protects excluded assets (e.g. a
        program that lists *.target.com in-scope but carves out admin.target.com).
        """
        if not self.configured:
            raise OutOfScope(
                "No scope configured. Ask the operator for the program's in-scope / "
                "out-of-scope / rules and call set_scope first. Hard safety gate."
            )
        parts = urlsplit(url if "://" in url else "//" + url, scheme="https")
        host = parts.hostname
        if not host:
            raise OutOfScope(f"Cannot parse host from {url!r}")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        for rule in self.deny:
            if rule.matches(host, port):
                raise OutOfScope(
                    f"{host}:{port} matches an OUT-OF-SCOPE rule ({rule.raw}). Excluded "
                    "assets are never contacted, even if an in-scope rule also matches."
                )
        for rule in self.rules:
            if rule.matches(host, port):
                return host, port
        raise OutOfScope(
            f"{host}:{port} is not in the allowlist. In-scope rules: "
            + ", ".join(r.raw for r in self.rules)
        )

    def describe(self) -> str:
        if not self.configured:
            return "SCOPE: (none configured - all requests blocked; call set_scope first)"
        s = "IN-SCOPE: " + ", ".join(r.raw for r in self.rules)
        if self.deny:
            s += "\nOUT-OF-SCOPE: " + ", ".join(r.raw for r in self.deny)
        return s
