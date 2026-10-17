"""Content safety filter and untrusted-content sanitisation.

The filter keeps CSAM and comparable illegal material out of results, fetches
and LLM input. Sanitisation strips zero-width/bidi characters and neutralises
prompt-delimiter tokens so scraped content cannot escape its data envelope.
"""
from __future__ import annotations

import re
from typing import List, Tuple

UNTRUSTED_OPEN = "<untrusted_darkweb_content>"
UNTRUSTED_CLOSE = "</untrusted_darkweb_content>"

_ZERO_WIDTH_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)

BLOCKED_PHRASES = (
    "csam", "child porn", "childporn", "child sex", "child nude", "child erotica",
    "child model", "child abuse images", "child rape", "child torture",
    "underage sex", "underage nude", "underage porn", "underage girl",
    "preteen nude", "preteen sex", "teens sex", "teen nude", "teen porn",
    "jailbait", "lolicon", "shotacon", "hurtcore", "boylover", "girllover",
    "snuff film", "snuff video", "red room", "toddler sex", "infant sex",
    "baby sex", "kids porn", "kids sex", "minor rape", "minor sex",
    "rape video", "rape porn", "torture porn", "bestiality porn",
)

BLOCKED_WORDS = frozenset({
    "pedo", "pedophile", "pedophilia", "underaged", "preteen", "toddler",
    "lolita", "childlove", "childlover", "kindersex", "bestiality",
})

BLOCKED_SUBSTRINGS = (
    "onlykids", "kindersex", "childlover", "childlove", "lolitaire",
)

BLOCKED_TOKEN_PAIRS = (
    ("child", "porn"), ("child", "sex"), ("child", "nude"), ("child", "rape"),
    ("child", "torture"), ("minor", "sex"), ("minor", "rape"),
    ("underage", "sex"), ("underage", "nude"), ("kids", "sex"),
    ("kids", "porn"), ("preteen", "nude"), ("teen", "nude"),
    ("toddler", "sex"), ("baby", "rape"), ("kids", "child"),
    ("only", "kids"), ("kids", "market"), ("kids", "shop"),
    ("kids", "videos"), ("kids", "collection"), ("young", "girls"),
)

SAFETY_NOTE = (
    "Content safety filter active: CSAM and comparable illegal material is "
    "excluded from results, fetches and LLM input."
)

_BLOCKED_WORD_RE = re.compile(r"\b(%s)\b" % "|".join(sorted(BLOCKED_WORDS)))


def sanitize_untrusted(text: str) -> str:
    """Normalise untrusted scraped text before safety checks or LLM prompts.

    Removes zero-width and bidi characters (a common evasion trick) and
    neutralises this tool's own prompt-delimiter tokens so content cannot
    break out of its data envelope.
    """
    cleaned = _ZERO_WIDTH_RE.sub("", text or "")
    cleaned = cleaned.replace(UNTRUSTED_OPEN, "[untrusted_darkweb_content]")
    cleaned = cleaned.replace(UNTRUSTED_CLOSE, "[/untrusted_darkweb_content]")
    return cleaned


def is_safe_text(text: str) -> bool:
    lowered = sanitize_untrusted(text).lower()
    if not lowered:
        return True
    if any(phrase in lowered for phrase in BLOCKED_PHRASES):
        return False
    if _BLOCKED_WORD_RE.search(lowered):
        return False
    if any(fragment in lowered for fragment in BLOCKED_SUBSTRINGS):
        return False
    tokens = set(re.findall(r"[a-z]+", lowered))
    for first, second in BLOCKED_TOKEN_PAIRS:
        if first in tokens and second in tokens:
            return False
    return True


def is_safe_result(result: dict) -> bool:
    haystack = " ".join([
        str(result.get("title", "")),
        str(result.get("snippet", "")),
        str(result.get("url", "")),
        str(result.get("engine", "")),
    ])
    return is_safe_text(haystack)


def filter_results(results: List[dict]) -> Tuple[List[dict], int]:
    kept: List[dict] = []
    dropped = 0
    for result in results:
        if is_safe_result(result):
            kept.append(result)
        else:
            dropped += 1
    return kept, dropped
