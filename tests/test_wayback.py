"""Offline protocol and safety tests for Internet Archive CDX discovery."""

from __future__ import annotations

import httpx
import pytest

from wafmcp.scope import OutOfScope, Scope
from wafmcp.wayback import WaybackError, fetch_wayback_urls


HEADER = ["timestamp", "original", "statuscode", "mimetype"]


def _scope(allow: str, deny: str = "") -> Scope:
    scope = Scope()
    scope.configure(allow, deny)
    return scope


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_host_query_deduplicates_and_never_returns_other_hosts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        params = request.url.params
        assert str(request.url).startswith("https://web.archive.org/cdx/search/cdx?")
        assert params["url"] == "example.com"
        assert params["matchType"] == "host"
        assert params["collapse"] == "urlkey"
        assert params["fl"] == "timestamp,original,statuscode,mimetype"
        assert params["limit"] == "10"
        return httpx.Response(
            200,
            json=[
                HEADER,
                ["20200101000000", "https://example.com/a", "200", "text/html"],
                ["20210101000000", "https://example.com/a", "200", "text/html"],
                ["20220101000000", "https://sub.example.com/x", "200", "text/html"],
                ["20230101000000", "ftp://example.com/file", "200", "text/plain"],
                ["20240101000000", "http://[malformed", "200", "text/plain"],
            ],
        )

    with _client(handler) as client:
        result = fetch_wayback_urls(_scope("example.com"), "example.com", limit=10, client=client)

    assert [record.url for record in result.records] == ["https://example.com/a"]
    assert result.duplicates_removed == 1
    assert result.filtered_out_of_scope == 1
    assert result.filtered_invalid == 2
    assert result.raw_captures == 5
    assert not result.possible_truncation
    assert "none of the returned URLs were contacted" in result.to_dict()["note"]


def test_domain_query_respects_wildcard_and_deny_override() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["matchType"] == "domain"
        return httpx.Response(
            200,
            json=[
                HEADER,
                ["20200101000000", "https://example.com/", "200", "text/html"],
                ["20200101000000", "https://api.example.com/v1", "200", "application/json"],
                ["20200101000000", "https://admin.example.com/", "200", "text/html"],
                ["20200101000000", "https://example.com.evil.test/", "200", "text/html"],
            ],
        )

    scope = _scope("example.com, *.example.com", "admin.example.com")
    with _client(handler) as client:
        result = fetch_wayback_urls(
            scope, "example.com", include_subdomains=True, limit=20, client=client
        )

    assert [record.url for record in result.records] == [
        "https://api.example.com/v1",
        "https://example.com/",
    ]
    assert result.filtered_out_of_scope == 2


def test_timestamp_and_status_filters_are_sent_and_enforced() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        params = request.url.params
        assert params["from"] == "2020"
        assert params["to"] == "20211231"
        assert params["filter"] == "statuscode:200"
        return httpx.Response(
            200,
            json=[
                HEADER,
                ["20200101000000", "https://example.com/ok", "200", "text/html"],
                ["20200101000000", "https://example.com/missing", "404", "text/html"],
            ],
        )

    with _client(handler) as client:
        result = fetch_wayback_urls(
            _scope("example.com"),
            "https://example.com/some/path",
            limit=2,
            from_timestamp="2020",
            to_timestamp="20211231",
            status_code=200,
            client=client,
        )

    assert [record.url for record in result.records] == ["https://example.com/ok"]
    assert result.filtered_invalid == 1
    assert result.possible_truncation


def test_out_of_scope_target_is_rejected_before_archive_request() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json=[])

    with _client(handler) as client:
        with pytest.raises(OutOfScope):
            fetch_wayback_urls(_scope("allowed.example"), "blocked.example", client=client)
    assert not called


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"limit": 0}, "limit"),
        ({"limit": 5001}, "limit"),
        ({"timeout": 0.5}, "timeout"),
        ({"status_code": 99}, "status_code"),
        ({"from_timestamp": "2020-01"}, "from_timestamp"),
    ],
)
def test_input_validation(kwargs, message) -> None:
    with pytest.raises(ValueError, match=message):
        fetch_wayback_urls(_scope("example.com"), "example.com", **kwargs)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(503, text="busy"),
        httpx.Response(200, text="not-json"),
        httpx.Response(200, json={"unexpected": True}),
        httpx.Response(200, json=[["original"], ["https://example.com/"]]),
    ],
)
def test_cdx_failures_are_explicit(response: httpx.Response) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return response

    with _client(handler) as client:
        with pytest.raises(WaybackError):
            fetch_wayback_urls(_scope("example.com"), "example.com", client=client)
