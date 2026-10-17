"""Text and URL helpers — pure stdlib, no network access."""
from __future__ import annotations

import hashlib
import re
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

STOPWORDS = frozenset({
    "the", "and", "or", "in", "on", "at", "to", "a", "an", "of", "for", "is",
    "are", "was", "were", "be", "been", "being", "have", "has", "had", "do",
    "does", "did", "will", "would", "could", "should", "may", "might", "can",
    "this", "that", "these", "those", "it", "its", "from", "with", "as", "by",
    "about", "into", "through", "during", "before", "after", "above", "below",
    "between", "each", "all", "both", "few", "more", "most", "no", "not",
    "only", "same", "so", "than", "too", "very", "just", "but", "if", "then",
    "because", "our", "your", "their", "my", "his", "her", "we", "you", "they",
    "who", "which", "www", "com", "http", "https", "onion", "html", "php",
    "page", "site", "click", "here", "link", "home", "login", "register",
    "forum", "thread", "reply", "post", "message", "user", "admin", "index",
})

_QUERY_STOPWORDS = (STOPWORDS - frozenset({
    "site", "page", "link", "post", "home", "user", "admin",
})) | frozenset({
    "who", "which", "what", "where", "when", "why", "how", "whom", "whose",
    "any", "some", "me", "us", "them", "there", "here", "get", "got", "want",
    "know", "find", "looking", "search", "please", "tell", "show",
})

_TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "ref", "referrer",
})

_ONION_URL_RE = re.compile(
    r"^https?://([a-z2-7]{16}|[a-z2-7]{56})\.onion(?::\d+)?(?:[/?#]|$)", re.IGNORECASE
)

_REDIRECT_PARAMS = ("redirect_url", "uddg", "url", "u", "go", "target", "link")


def is_onion_url(url: str) -> bool:
    return bool(_ONION_URL_RE.match((url or "").strip()))


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def normalize_url(url: str) -> str:
    """Canonical form used for de-duplication (scheme-agnostic for .onion)."""
    raw = (url or "").strip()
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw.lower()
    host = (parts.hostname or "").lower()
    scheme = "" if host.endswith(".onion") else (parts.scheme or "http")
    path = parts.path.rstrip("/")
    query = ""
    if parts.query:
        kept = [kv for kv in parse_qsl(parts.query, keep_blank_values=True)
                if kv[0] not in _TRACKING_PARAMS]
        if kept:
            query = urlencode(sorted(kept))
    netloc = host
    if parts.port and parts.port not in (80, 443):
        netloc = "%s:%d" % (host, parts.port)
    return urlunsplit((scheme, netloc, path, query, ""))


def resolve_redirect(href: str) -> str:
    """Extract the real destination from common search-engine redirect wrappers."""
    try:
        parts = urlsplit(href)
    except ValueError:
        return href
    if not parts.query:
        return href
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    for key in _REDIRECT_PARAMS:
        candidate = params.get(key)
        if candidate and candidate.startswith(("http://", "https://")):
            return candidate
    return href


def absolutize(base: str, href: str) -> str:
    if not href or href.startswith(("javascript:", "mailto:", "data:")):
        return ""
    href = resolve_redirect(href)
    if href.startswith(("http://", "https://")):
        return href
    if not base:
        return ""
    return urljoin(base if base.endswith("/") else base + "/", href)


def clean_html_text(html: str, limit: Optional[int] = None) -> str:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup(["script", "style", "noscript", "template", "svg",
                     "nav", "footer", "header", "aside", "form"]):
        tag.decompose()
    text = soup.get_text("\n", strip=True)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if limit and len(text) > limit:
        text = text[:limit].rsplit("\n", 1)[0] if "\n" in text[:limit] else text[:limit]
        text = text.rstrip() + "\n[... truncated ...]"
    return text


def page_title(html: str) -> str:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html or "", "html.parser")
    if soup.title and soup.title.string:
        return re.sub(r"\s+", " ", soup.title.string).strip()[:300]
    return ""


def extract_keywords(text: str, top_n: int = 20) -> List[str]:
    tokens = [t for t in re.findall(r"[a-z0-9]{3,}", (text or "").lower())
              if t not in STOPWORDS]
    counts = Counter(tokens)
    return [word for word, _ in counts.most_common(top_n)]


def heuristic_query(query: str, max_words: int = 5) -> str:
    """Offline fallback for query refinement: drop stopwords, keep order."""
    words = re.findall(r"\S+", (query or "").strip())
    picked = [w for w in words
              if w.lower().strip("?!.,:;'\"") not in _QUERY_STOPWORDS]
    if not picked:
        picked = words
    return " ".join(picked[:max_words]) or (query or "").strip()


def score_results(query: str, results: List[dict],
                  texts: Optional[Dict[str, str]] = None) -> List[dict]:
    """BM25-style relevance scoring; adds a ``score`` key (0..1) and sorts."""
    if isinstance(query, (list, tuple)):
        query = " ".join(str(q) for q in query)
    qset = set(t for t in re.findall(r"[a-z0-9]{3,}", (query or "").lower())
               if t not in STOPWORDS)
    if not qset:
        out = [dict(r) for r in results]
        for r in out:
            r.setdefault("score", 0.5)
        return out

    k1, b, avgdl = 1.5, 0.75, 12.0
    scored: List[dict] = []
    for result in results:
        page = ((texts or {}).get(result.get("url", ""), "") or "")[:2000]
        doc = " ".join([str(result.get("title", "")), str(result.get("snippet", "")),
                        str(result.get("url", "")), page]).lower()
        doc_tokens = re.findall(r"[a-z0-9]{3,}", doc)
        doc_len = max(len(doc_tokens), 1)
        counts = Counter(t for t in doc_tokens if t in qset)
        raw = 0.0
        for count in counts.values():
            raw += (count * (k1 + 1)) / (count + k1 * (1 - b + b * doc_len / avgdl))
        item = dict(result)
        corroboration = 1
        try:
            corroboration = max(1, int(result.get("corroboration", 1)))
        except (TypeError, ValueError):
            corroboration = 1
        bonus = min(0.1 * (corroboration - 1), 0.2)
        item["score"] = round(min(raw / (len(qset) + 1) + bonus, 1.0), 4)
        scored.append(item)
    scored.sort(key=lambda r: r.get("score", 0.0), reverse=True)
    return scored


def content_fingerprint(text: str) -> str:
    normalized = re.sub(r"\s+", " ", (text or "").lower()).strip()[:4096]
    return hashlib.md5(normalized.encode("utf-8", "replace"),
                       usedforsecurity=False).hexdigest()


def deduplicate(results: Iterable[dict]) -> List[dict]:
    seen = set()
    unique: List[dict] = []
    for result in results:
        url = str(result.get("url", ""))
        fingerprint = normalize_url(url)
        if not fingerprint or fingerprint in seen:
            if not fingerprint:
                continue
            continue
        seen.add(fingerprint)
        unique.append(dict(result))
    return unique


def truncate(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    return text[:limit] + "\n[... truncated ...]"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def timestamp() -> float:
    return time.time()


def friendly_error(error) -> str:
    """Translate raw socket/urllib3 noise into an actionable message."""
    message = str(error)
    patterns = (
        (r"Missing dependencies for SOCKS",
         "PySocks missing — install with: pip install requests[socks]"),
        (r"nodename nor servname|Name or service not known|Failed to resolve|"
         r"Name does not resolve|Temporary failure in name resolution",
         "Hidden service name did not resolve — the .onion address may be offline, "
         "invalid or barely reachable; try another result or renew the identity"),
        (r"timed out|Read timed out|timeout",
         "Timed out — the hidden service may be offline, or try renew.py"),
        (r"Connection refused|ConnectionRefused",
         "Connection refused — the hidden service is likely down"),
        (r"RemoteDisconnected|ConnectionReset|broken pipe",
         "Connection reset by the hidden service — it may be overloaded"),
        (r"SSL|certificate|cert verify|CERTIFICATE",
         "TLS error — many .onion services only serve plain HTTP, try http://"),
        (r"Max retries exceeded",
         "Unreachable after retries — the hidden service may be offline; "
         "run renew.py and try again"),
        (r"SOCKS5|SOCKS proxy|SOCKSHTTPConnection|SOCKSConnection",
         "Tor circuit unavailable — is `tor` running and listening on the SOCKS port?"),
        (r"Network is unreachable|No route to host",
         "Network unreachable — check your internet connection"),
        (r"control port|stem|authentication failed|Authenticating",
         "Tor control port auth failed — set TOR_CONTROL_PASSWORD or TOR_DATA_DIR in .env"),
    )
    for pattern, friendly in patterns:
        if re.search(pattern, message, re.IGNORECASE):
            return friendly
    return truncate(message, 200)
