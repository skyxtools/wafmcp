"""Program rules - the engagement constraints a bug-bounty / pentest program sets.

Scope says *where* you may test. Rules say *how*. Both are asked from the
operator before any probing starts. Rules are enforced at the transport layer so
the LLM cannot accidentally violate them:

  - max_rps:        hard client-side rate limit (requests/second) across all tools
  - required_headers: identification headers the program mandates (e.g. a bounty
                    handle: {"X-Bug-Bounty": "researcher-handle"})
  - forbidden_paths: substrings that must never be requested (e.g. "/admin",
                    "/logout", a destructive endpoint the program excludes)
  - forbidden_methods: HTTP methods the program disallows (e.g. DELETE, PUT)
  - notes:          free-text program caveats surfaced back to the LLM
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


class RuleViolation(Exception):
    """Raised when a request would break a program rule."""


@dataclass
class Rules:
    max_rps: float = 0.0                       # 0 = unlimited
    required_headers: dict[str, str] = field(default_factory=dict)
    forbidden_paths: list[str] = field(default_factory=list)
    forbidden_methods: list[str] = field(default_factory=list)
    notes: str = ""
    _last_ts: float = field(default=0.0, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def configured(self) -> bool:
        return bool(
            self.max_rps
            or self.required_headers
            or self.forbidden_paths
            or self.forbidden_methods
            or self.notes
        )

    def enforce(self, method: str, url: str) -> None:
        """Raise RuleViolation if the request breaks a rule. Called before egress."""
        m = method.upper()
        if self.forbidden_methods and m in {x.upper() for x in self.forbidden_methods}:
            raise RuleViolation(f"method {m} is forbidden by program rules")
        low = url.lower()
        for frag in self.forbidden_paths:
            if frag.lower() in low:
                raise RuleViolation(
                    f"url matches a forbidden path fragment ({frag!r}) per program rules"
                )

    def throttle(self) -> None:
        """Block until the rate limit permits the next request."""
        if self.max_rps <= 0:
            return
        min_gap = 1.0 / self.max_rps
        with self._lock:
            now = time.monotonic()
            wait = self._last_ts + min_gap - now
            if wait > 0:
                time.sleep(wait)
            self._last_ts = time.monotonic()

    def inject_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Merge mandated identification headers (operator-set ones take priority
        only if the caller didn't already set that header explicitly)."""
        merged = dict(headers)
        lower = {k.lower() for k in merged}
        for k, v in self.required_headers.items():
            if k.lower() not in lower:
                merged[k] = v
        return merged

    def describe(self) -> str:
        if not self.configured:
            return "RULES: (none set)"
        parts = []
        if self.max_rps:
            parts.append(f"max_rps={self.max_rps}")
        if self.required_headers:
            parts.append(f"required_headers={list(self.required_headers)}")
        if self.forbidden_methods:
            parts.append(f"forbidden_methods={self.forbidden_methods}")
        if self.forbidden_paths:
            parts.append(f"forbidden_paths={self.forbidden_paths}")
        if self.notes:
            parts.append(f"notes={self.notes!r}")
        return "RULES: " + "; ".join(parts)

    def summary(self) -> dict[str, Any]:
        return {
            "max_rps": self.max_rps,
            "required_headers": self.required_headers,
            "forbidden_paths": self.forbidden_paths,
            "forbidden_methods": self.forbidden_methods,
            "notes": self.notes,
        }
