"""Dark-web search engine registry, result parsing and engine health checks."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional
from urllib.parse import quote_plus, urlsplit

from bs4 import BeautifulSoup

from .cache import get_cache
from .config import ENGINES_FILE, settings
from .safety import filter_results
from .textutil import (absolutize, deduplicate, friendly_error, host_of,
                       is_onion_url, normalize_url)
from .tor import build_session, request_timeout

_ENGINES: List[dict] = [
    {"name": "Ahmia", "kind": "onion",
     "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}",
     "note": "Curated index, filters abusive content — most reliable"},
    {"name": "OnionLand", "kind": "onion",
     "url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}",
     "note": "Clean text interface, volatile uptime"},
    {"name": "Amnesia", "kind": "onion",
     "url": "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}",
     "note": "Unfiltered index"},
    {"name": "Torland", "kind": "onion",
     "url": "http://torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd.onion/index.php?a=search&q={query}",
     "note": "Moderate index"},
    {"name": "Excavator", "kind": "onion",
     "url": "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}",
     "note": "Unfiltered index"},
    {"name": "Onionway", "kind": "onion",
     "url": "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}",
     "note": "Unfiltered index"},
    {"name": "Tor66", "kind": "onion",
     "url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}",
     "note": "Broad index, intermittent downtime"},
    {"name": "OSS", "kind": "onion",
     "url": "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/index.php?search={query}",
     "note": "Onion Search Server"},
    {"name": "Torgol", "kind": "onion",
     "url": "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}",
     "note": "Unfiltered index"},
    {"name": "TheDeepSearches", "kind": "onion",
     "url": "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}",
     "note": "Aggregating index"},
]


def _load_extra_engines() -> List[dict]:
    """Merge an optional engines.json (repo root): same names override, new append."""
    if not ENGINES_FILE.is_file():
        return list(_ENGINES)
    try:
        payload = json.loads(ENGINES_FILE.read_text(encoding="utf-8"))
        overrides = payload if isinstance(payload, list) else payload.get("engines", [])
    except (OSError, ValueError):
        return list(_ENGINES)

    engines = [dict(engine) for engine in _ENGINES]
    by_name = {engine["name"].lower(): position for position, engine in enumerate(engines)}
    for entry in overrides:
        if not isinstance(entry, dict) or "name" not in entry or "url" not in entry:
            continue
        name = str(entry["name"])
        merged = {"name": name, "kind": str(entry.get("kind", "onion")),
                  "url": str(entry["url"]), "note": str(entry.get("note", "user-defined"))}
        if not merged["url"].startswith(("http://", "https://")):
            continue
        position = by_name.get(name.lower())
        if position is None:
            by_name[name.lower()] = len(engines)
            engines.append(merged)
        else:
            engines[position] = merged
    return engines


ENGINES = _load_extra_engines()
ENGINE_NAMES = [engine["name"] for engine in ENGINES]


def engine_base(engine: dict) -> str:
    parts = urlsplit(engine["url"])
    path = parts.path or "/"
    directory = path.rsplit("/", 1)[0] + "/"
    root = "%s://%s%s" % (parts.scheme, parts.netloc, directory)
    return root


def resolve_engines(names: Optional[List[str]]) -> List[dict]:
    if not names:
        return list(ENGINES)
    wanted = {name.strip().lower() for name in names}
    return [engine for engine in ENGINES if engine["name"].lower() in wanted]


def _keep_link(url: str, kind: str, own_host: str) -> bool:
    host = host_of(url)
    if not host or host == own_host:
        return False
    if is_onion_url(url):
        return True
    if kind != "clearnet":
        return False
    return url.startswith(("http://", "https://"))


_JS_MARKERS = (
    "non-javascript version", "non-javascript", "enable javascript",
    "requires javascript", "javascript is disabled", "javascript must be enabled",
)

_RESULT_CONTAINERS = ("li.result", "div.result", "article", ".results li",
                      "table tr", "h2 a", "h3 a", "h4 a")


def looks_js_only(html: str) -> bool:
    """Detect interstitials that need a real browser (no server-side results)."""
    lowered = (html or "").lower()
    return any(marker in lowered for marker in _JS_MARKERS)


def _result_anchors(soup) -> list:
    """Prefer anchors inside result containers; fall back to all page anchors."""
    picked, seen = [], set()
    for selector in _RESULT_CONTAINERS:
        for container in soup.select(selector):
            for anchor in container.find_all("a", href=True):
                anchor_id = id(anchor)
                if anchor_id in seen:
                    continue
                seen.add(anchor_id)
                picked.append(anchor)
    return picked or soup.find_all("a", href=True)


def parse_results(html: str, engine: dict) -> List[dict]:
    """Extract ``{title, url, engine}`` candidates from an engine's result HTML."""
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup(["script", "style", "noscript", "template", "svg",
                     "nav", "footer", "header", "aside", "form"]):
        tag.decompose()
    base = engine_base(engine)
    own_host = host_of(engine["url"])
    results: List[dict] = []
    for anchor in _result_anchors(soup):
        href = anchor["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "data:")):
            continue
        url = absolutize(base, href)
        if not url or not _keep_link(url, engine.get("kind", "onion"), own_host):
            continue
        title = anchor.get_text(" ", strip=True)
        if not title:
            near = anchor.find_parent(["h2", "h3", "h4", "li", "article", "div"])
            if near is not None:
                title = near.get_text(" ", strip=True)
        results.append({
            "title": title[:250] or host_of(url),
            "url": url,
            "engine": engine["name"],
        })
        if len(results) >= settings.engine_max_results * 2:
            break
    results = deduplicate(results)[:settings.engine_max_results]
    kept, _ = filter_results(results)
    return kept


def query_engine(engine: dict, query: str, record: bool = True) -> Dict[str, object]:
    url = engine["url"].format(query=quote_plus(query))
    started = time.time()
    session = build_session(isolate_tag="engine-%s" % engine["name"])
    status, error, results = "up", None, []
    try:
        response = session.get(url, timeout=request_timeout())
        latency_ms = int((time.time() - started) * 1000)
        if response.status_code >= 400:
            status = "down"
            error = "HTTP %d" % response.status_code
        else:
            results = parse_results(response.text, engine)
            if not results and looks_js_only(response.text):
                status = "down"
                error = "JS-only page — no server-side results without a browser"
    except Exception as exc:
        latency_ms = int((time.time() - started) * 1000)
        status, error = "down", friendly_error(exc)
    finally:
        session.close()

    if record:
        try:
            get_cache().engine_record(engine["name"], status,
                                      latency_ms if status == "up" else None, error)
        except Exception:
            pass

    return {
        "engine": engine["name"],
        "status": status,
        "latency_ms": latency_ms,
        "count": len(results),
        "results": results,
        "error": error,
    }


def check_search_engines(cached_minutes: int = 0,
                         names: Optional[List[str]] = None,
                         test_query: str = "onion",
                         workers: int = 6,
                         on_result: Optional[Callable[[dict], None]] = None) -> Dict[str, object]:
    """Ping every engine with a test query and report status + latency."""
    cache = get_cache()
    selected = resolve_engines(names)
    cache_key = "check:" + ",".join(sorted(engine["name"] for engine in selected))

    if cached_minutes > 0:
        cached = cache.get(cache_key, "engine", cached_minutes * 60)
        if cached:
            cached["cached"] = True
            return cached

    checks: List[dict] = []
    with ThreadPoolExecutor(max_workers=max(2, workers)) as pool:
        futures = {pool.submit(query_engine, engine, test_query): engine
                   for engine in selected}
        for future in as_completed(futures):
            engine = futures[future]
            try:
                outcome = future.result()
            except Exception as exc:
                outcome = {"engine": engine["name"], "status": "down",
                           "latency_ms": None, "count": 0, "results": [],
                           "error": friendly_error(exc)}
            checks.append({
                "name": outcome["engine"],
                "status": outcome["status"],
                "latency_ms": outcome["latency_ms"],
                "count": outcome["count"],
                "error": outcome["error"],
                "reliability": cache.engine_reliability(outcome["engine"]),
            })
            if on_result:
                on_result(checks[-1])

    checks.sort(key=lambda item: (item["status"] != "up",
                                  item["latency_ms"] or 10 ** 9))
    report = {
        "alive": sum(1 for item in checks if item["status"] == "up"),
        "total": len(checks),
        "test_query": test_query,
        "checked_at": time.time(),
        "results": checks,
        "cached": False,
    }
    cache.set(cache_key, "engine", report)
    return report
