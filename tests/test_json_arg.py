"""Tests for _json_arg — tolerant parsing of *_json tool args.

Real-world: some MCP clients pass the declared JSON string, others pre-parse it
into a dict before it reaches the tool. header_json broke because only a string
was accepted. This locks in tolerance for both.
"""
import pytest

from wafmcp.server import _json_arg


def test_parses_json_string():
    assert _json_arg('{"X-Api-Key": "abc"}', "header_json") == {"X-Api-Key": "abc"}


def test_accepts_dict_already_parsed_by_sdk():
    d = {"Authorization": "Bearer x"}
    assert _json_arg(d, "header_json") is d


def test_accepts_list():
    assert _json_arg([1, 2], "x") == [1, 2]


def test_none_and_empty_return_none():
    assert _json_arg(None, "x") is None
    assert _json_arg("", "x") is None


def test_single_quoted_dict_repr_fallback():
    assert _json_arg("{'X-Debug': 'on'}", "header_json") == {"X-Debug": "on"}


def test_invalid_raises_valueerror():
    with pytest.raises(ValueError):
        _json_arg("not json at all", "header_json")
