"""Multi-engine dark-web search with caching and de-duplication."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

from .cache import get_cache
from .config import settings
from .engines import ENGINE_NAMES, query_engine, resolve_engines
from .tor import require_tor
from .textutil import deduplicate, friendly_error, host_of, score_results


def _cache_key(query: str, engine_names: List[str]) -> str:
    return json.dumps({"q": query.strip().lower(), "engines": sorted(engine_names)},
                      ensure_ascii=False)


def add_corroboration(results: List[dict]) -> List[dict]:
    """Count how many independent engines returned the same host.

    A host surfaced by several engines is far less likely to be index spam —
    the count feeds a small bonus in ``score_results``.
    """
    by_host: Dict[str, set] = {}
    for row in results:
        by_host.setdefault(host_of(str(row.get("url", ""))), set()).add(
            str(row.get("engine", "?")))
    for row in results:
        engines = sorted(by_host.get(host_of(str(row.get("url", ""))), set()))
        row["corroboration"] = max(1, len(engines))
        row["engines"] = engines
    return results


def search_detailed(query: str,
                    engines: Optional[List[str]] = None,
                    max_results: int = 0,
                    workers: Optional[int] = None,
                    use_cache: bool = True,
                    on_engine: Optional[Callable[[dict], None]] = None) -> Dict[str, object]:
    """Search every selected engine in parallel and return a detailed report."""
    query = (query or "").strip()
    if not query:
        return {"ok": False, "query": query, "results": [], "per_engine": {},
                "error": "empty query"}

    selected = resolve_engines(engines)
    if not selected:
        return {"ok": False, "query": query, "results": [], "per_engine": {},
                "error": "no matching engines — known: %s" % ", ".join(ENGINE_NAMES)}

    try:
        require_tor()
    except RuntimeError as exc:
        return {"ok": False, "query": query, "results": [], "per_engine": {},
                "error": str(exc)}

    cache = get_cache()
    key = _cache_key(query, [engine["name"] for engine in selected])
    if use_cache:
        cached = cache.get(key, "search", settings.search_cache_ttl)
        if cached:
            cached["cached"] = True
            if max_results:
                cached["results"] = cached["results"][:max_results]
            return cached

    per_engine: Dict[str, dict] = {}
    all_results: List[dict] = []
    started = time.time()
    with ThreadPoolExecutor(max_workers=max(2, workers or settings.search_workers)) as pool:
        futures = {pool.submit(query_engine, engine, query): engine for engine in selected}
        for future in as_completed(futures):
            engine = futures[future]
            try:
                outcome = future.result()
            except Exception as exc:
                outcome = {"engine": engine["name"], "status": "down", "latency_ms": None,
                           "count": 0, "results": [], "error": friendly_error(exc)}
            per_engine[outcome["engine"]] = {
                "status": outcome["status"],
                "latency_ms": outcome["latency_ms"],
                "count": outcome["count"],
                "error": outcome["error"],
            }
            all_results.extend(outcome["results"])
            if on_engine:
                on_engine(per_engine[outcome["engine"]] | {"engine": outcome["engine"]})

    results = deduplicate(all_results)
    results = add_corroboration(results)
    results = score_results(query, results)
    report = {
        "ok": True,
        "query": query,
        "engines": [engine["name"] for engine in selected],
        "per_engine": per_engine,
        "count": len(results),
        "results": results,
        "elapsed_s": round(time.time() - started, 1),
        "cached": False,
        "error": None,
    }
    cache.set(key, "search", report)

    if max_results:
        report["results"] = report["results"][:max_results]
    return report


def search(query: str,
           engines: Optional[List[str]] = None,
           max_results: int = 0,
           workers: Optional[int] = None,
           use_cache: bool = True) -> List[dict]:
    """Search dark-web engines and return de-duplicated ``{title,url,engine}`` rows."""
    report = search_detailed(query, engines=engines, max_results=max_results,
                             workers=workers, use_cache=use_cache)
    return report.get("results", [])
