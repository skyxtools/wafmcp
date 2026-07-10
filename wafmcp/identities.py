"""Identities - named authenticated sessions for access-control testing.

Most bug-bounty findings live behind auth. To test IDOR / broken access control
we need to replay the SAME request as different principals and compare. An
identity is just a bundle of headers (a Cookie, a Bearer token, custom auth
headers) plus an optional label.

The reserved identity "" (empty / None) means UNAUTHENTICATED - used as the
control that proves an endpoint is actually protected (not simply public).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Identity:
    name: str
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_anon(self) -> bool:
        return not self.headers


class IdentityStore:
    def __init__(self) -> None:
        self._ids: dict[str, Identity] = {}

    def set(self, name: str, headers: dict[str, str], cookie: str | None = None) -> Identity:
        h = dict(headers or {})
        if cookie:
            h["Cookie"] = cookie
        ident = Identity(name=name, headers=h)
        self._ids[name] = ident
        return ident

    def get(self, name: str | None) -> Identity:
        if not name:
            return Identity(name="anonymous", headers={})
        if name not in self._ids:
            raise KeyError(f"unknown identity {name!r}; set it with set_identity first")
        return self._ids[name]

    def names(self) -> list[str]:
        return list(self._ids)

    def describe(self) -> str:
        if not self._ids:
            return "IDENTITIES: (none set)"
        return "IDENTITIES: " + ", ".join(
            f"{n}[{', '.join(i.headers) or 'anon'}]" for n, i in self._ids.items()
        )
