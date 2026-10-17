"""Fetch .onion / clearnet pages through Tor and extract readable content."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .cache import get_cache
from .config import settings
from .safety import is_safe_text
from .textutil import (clean_html_text, friendly_error, host_of, page_title,
                       truncate)
from .tor import build_session, request_timeout

BLOCKED_MESSAGE = ("Page withheld by the content safety filter "
                   "(illegal material indicators detected).")


def _record_evidence(url: str, status: int, raw_bytes: bytes, body: str) -> None:
    """Append a hash-chained provenance record; never let logging break a fetch."""
    if not settings.evidence_enabled or status == 0:
        return
    try:
        from .evidence import get_log

        get_log().record_fetch(url, status, raw_bytes, page_title(body))
    except Exception:
        pass


def _body_hash(raw_bytes: bytes) -> Optional[str]:
    if not raw_bytes:
        return None
    try:
        from .evidence import sha256_hex

        return sha256_hex(raw_bytes)
    except Exception:
        return None


def _extract_links(html: str, base_url: str) -> List[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    links: List[str] = []
    seen = set()
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "data:")):
            continue
        url = urljoin(base_url, href)
        if not url.startswith(("http://", "https://")) or url in seen:
            continue
        seen.add(url)
        links.append(url)
        if len(links) >= 200:
            break
    return links


def fetch(url: str,
          extract_links: bool = False,
          max_chars: Optional[int] = None,
          use_cache: bool = True,
          session=None,
          timeout=None) -> Dict[str, object]:
    """Fetch one URL through Tor.

    Returns ``{ok, url, status, title, text, links, cached, error}``; ``status``
    is 0 when the request never completed.
    """
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        return {"ok": False, "url": url, "status": 0, "title": "", "text": "",
                "links": [], "cached": False, "error": "URL must start with http:// or https://"}

    limit = max_chars or settings.max_content_chars
    cache = get_cache()
    cache_key = json.dumps({"url": url, "links": extract_links, "max": limit})
    if use_cache:
        cached = cache.get(cache_key, "fetch", settings.fetch_cache_ttl)
        if cached:
            cached["cached"] = True
            return cached

    owns_session = session is None
    session = session or build_session(isolate_tag="fetch")
    status_code, body, error = 0, "", None
    raw_bytes = b""
    try:
        response = session.get(url, timeout=timeout or request_timeout(),
                               allow_redirects=True)
        status_code = response.status_code
        raw_bytes = response.content or b""
        if response.encoding is None or response.encoding.lower() == "iso-8859-1":
            response.encoding = response.apparent_encoding or "utf-8"
        body = response.text or ""
    except Exception as exc:
        error = friendly_error(exc)
    finally:
        if owns_session:
            session.close()

    _record_evidence(url, status_code, raw_bytes, body)

    if status_code == 0:
        return {"ok": False, "url": url, "status": 0, "title": "", "text": "",
                "links": [], "cached": False, "error": error}

    text = clean_html_text(body)
    if not is_safe_text(text) or not is_safe_text(page_title(body)):
        result = {"ok": False, "url": url, "status": status_code, "title": "",
                  "text": "", "links": [], "cached": False,
                  "error": BLOCKED_MESSAGE, "blocked": True}
        cache.set(cache_key, "fetch", result)
        return result

    title = page_title(body)
    if title and not is_safe_text(title):
        title = ""
    result = {
        "ok": 200 <= status_code < 400,
        "url": url,
        "status": status_code,
        "title": title,
        "text": truncate(text, limit),
        "links": _extract_links(body, url) if extract_links else [],
        "host": host_of(url),
        "sha256": _body_hash(raw_bytes),
        "bytes": len(raw_bytes),
        "cached": False,
        "error": None if 200 <= status_code < 400 else "HTTP %d" % status_code,
    }
    cache.set(cache_key, "fetch", result)
    return result


def scrape_all(urls: List[str],
               workers: Optional[int] = None,
               max_chars: Optional[int] = None,
               use_cache: bool = True,
               on_page: Optional[Callable[[dict], None]] = None) -> Dict[str, str]:
    """Concurrently fetch many URLs; returns ``{url: text}`` for successes only."""
    texts: Dict[str, str] = {}
    unique_urls = list(dict.fromkeys(url for url in urls if url))
    if not unique_urls:
        return texts

    with ThreadPoolExecutor(max_workers=max(1, workers or settings.scrape_workers)) as pool:
        futures = {pool.submit(fetch, url, False, max_chars, use_cache): url
                   for url in unique_urls}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:
                result = {"ok": False, "url": futures[future], "error": friendly_error(exc)}
            if on_page:
                on_page(result)
            if result.get("ok") and result.get("text"):
                texts[result["url"]] = result["text"]
    return texts
