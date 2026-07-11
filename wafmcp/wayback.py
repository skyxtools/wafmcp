"""Passive URL discovery through the Internet Archive Wayback CDX API.

Only the archive index is queried. Returned URLs are validated against the
operator-confirmed scope and are never requested by this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import __version__
from .scope import OutOfScope, Scope


CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
MAX_RESULTS = 5_000
_TIMESTAMP_RE = re.compile(r"^\d{1,14}$")


class WaybackError(RuntimeError):
    """The CDX request or response could not be processed."""


@dataclass
class WaybackRecord:
    url: str
    timestamp: str
    status_code: str
    mimetype: str

    def to_dict(self) -> dict[str, str]:
        return {
            "url": self.url,
            "timestamp": self.timestamp,
            "status_code": self.status_code,
            "mimetype": self.mimetype,
        }


@dataclass
class WaybackResult:
    target: str
    include_subdomains: bool
    requested_limit: int
    records: list[WaybackRecord] = field(default_factory=list)
    raw_captures: int = 0
    filtered_out_of_scope: int = 0
    filtered_invalid: int = 0
    duplicates_removed: int = 0
    possible_truncation: bool = False
    query: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": "internet_archive_cdx",
            "target": self.target,
            "include_subdomains": self.include_subdomains,
            "requested_limit": self.requested_limit,
            "returned": len(self.records),
            "raw_captures": self.raw_captures,
            "filtered_out_of_scope": self.filtered_out_of_scope,
            "filtered_invalid": self.filtered_invalid,
            "duplicates_removed": self.duplicates_removed,
            "possible_truncation": self.possible_truncation,
            "query": self.query,
            "records": [record.to_dict() for record in self.records],
            "note": (
                "Passive discovery only: queried the Internet Archive CDX index; "
                "none of the returned URLs were contacted."
            ),
        }


def _validate_timestamp(value: str | None, name: str) -> str | None:
    if value is None or value == "":
        return None
    value = str(value)
    if not _TIMESTAMP_RE.fullmatch(value):
        raise ValueError(f"{name} must contain 1-14 digits (Wayback timestamp format)")
    return value


def _target_host(scope: Scope, target: str) -> tuple[str, str]:
    raw = target.strip()
    if not raw:
        raise ValueError("target is required")
    candidate = raw if "://" in raw else f"https://{raw}"
    parts = urlsplit(candidate)
    if not parts.hostname or parts.username or parts.password:
        raise ValueError(f"cannot parse a safe host from target {target!r}")
    scope.check(candidate)
    query_host = parts.hostname.lower()
    if parts.port is not None:
        query_host = f"{query_host}:{parts.port}"
    return parts.hostname.lower(), query_host


def fetch_wayback_urls(
    scope: Scope,
    target: str,
    *,
    include_subdomains: bool = False,
    limit: int = 1_000,
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    status_code: int | None = None,
    timeout: float = 25.0,
    client: httpx.Client | None = None,
) -> WaybackResult:
    """Fetch unique archived URLs for an in-scope host from the CDX index."""
    if not 1 <= limit <= MAX_RESULTS:
        raise ValueError(f"limit must be between 1 and {MAX_RESULTS}")
    if not 1.0 <= timeout <= 60.0:
        raise ValueError("timeout must be between 1 and 60 seconds")
    if status_code is not None and not 100 <= status_code <= 599:
        raise ValueError("status_code must be between 100 and 599")
    start = _validate_timestamp(from_timestamp, "from_timestamp")
    end = _validate_timestamp(to_timestamp, "to_timestamp")
    host, query_host = _target_host(scope, target)

    params: list[tuple[str, str]] = [
        ("url", host if include_subdomains else query_host),
        ("matchType", "domain" if include_subdomains else "host"),
        ("output", "json"),
        ("fl", "timestamp,original,statuscode,mimetype"),
        ("collapse", "urlkey"),
        ("limit", str(limit)),
    ]
    if start:
        params.append(("from", start))
    if end:
        params.append(("to", end))
    if status_code is not None:
        params.append(("filter", f"statuscode:{status_code}"))

    owned_client = client is None
    if client is None:
        client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "Accept": "application/json",
                "User-Agent": (
                    f"wafmcp-wayback/{__version__} "
                    "(+https://github.com/skyxtools/wafmcp)"
                ),
            },
        )
    try:
        try:
            response = client.get(CDX_ENDPOINT, params=params)
        except httpx.HTTPError as exc:
            raise WaybackError(f"CDX request failed: {exc}") from exc
        if response.status_code != 200:
            raise WaybackError(f"CDX API returned HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise WaybackError("CDX API returned invalid JSON") from exc
    finally:
        if owned_client:
            client.close()

    result = WaybackResult(
        target=query_host,
        include_subdomains=include_subdomains,
        requested_limit=limit,
        query={key: value for key, value in params if key != "filter"},
    )
    if status_code is not None:
        result.query["filter"] = f"statuscode:{status_code}"
    if payload == []:
        return result
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], list):
        raise WaybackError("CDX JSON did not contain a header row")

    header = payload[0]
    required = ("timestamp", "original", "statuscode", "mimetype")
    if not all(name in header for name in required):
        raise WaybackError("CDX JSON header is missing required fields")
    indexes = {name: header.index(name) for name in required}
    rows = payload[1:]
    result.raw_captures = len(rows)
    result.possible_truncation = len(rows) >= limit

    unique: dict[str, WaybackRecord] = {}
    for row in rows:
        if not isinstance(row, list) or any(indexes[name] >= len(row) for name in required):
            result.filtered_invalid += 1
            continue
        original = str(row[indexes["original"]])
        try:
            parts = urlsplit(original)
            archived_host = (parts.hostname or "").lower()
        except ValueError:
            result.filtered_invalid += 1
            continue
        if parts.scheme not in ("http", "https") or not archived_host:
            result.filtered_invalid += 1
            continue
        belongs_to_target = archived_host == host or (
            include_subdomains and archived_host.endswith(f".{host}")
        )
        if not belongs_to_target:
            result.filtered_out_of_scope += 1
            continue
        try:
            scope.check(original)
        except (OutOfScope, ValueError):
            result.filtered_out_of_scope += 1
            continue
        row_status = str(row[indexes["statuscode"]])
        if status_code is not None and row_status != str(status_code):
            result.filtered_invalid += 1
            continue
        if original in unique:
            result.duplicates_removed += 1
            continue
        unique[original] = WaybackRecord(
            url=original,
            timestamp=str(row[indexes["timestamp"]]),
            status_code=row_status,
            mimetype=str(row[indexes["mimetype"]]),
        )

    result.records = [unique[url] for url in sorted(unique)]
    return result
