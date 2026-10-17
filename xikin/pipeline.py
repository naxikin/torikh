"""Full investigation pipeline: verify Tor, check engines, refine, search,
filter, scrape and analyse — with graceful offline fallbacks."""
from __future__ import annotations

import os
import re
from typing import Callable, Dict, List, Optional

from . import __version__
from .cache import clear_cache
from .engines import check_search_engines
from .fetch import scrape_all
from .iocs import extract as extract_iocs
from .iocs import find_secret_hits, render_markdown as render_iocs, total_count as ioc_total
from .llm import (LLMError, ask, filter_results, llm_available, mode_config,
                  provider_summary, refine_query)
from .safety import SAFETY_NOTE
from .search import search_detailed
from .textutil import score_results, utc_now_iso
from .tor import check_tor


def _slug(text: str, limit: int = 40) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return slug[:limit] or "query"


def _fallback_report(query: str, mode: str, result_rows: List[dict],
                     scraped: Dict[str, str], errors: List[str]) -> str:
    lines = ["## Offline summary",
             "",
             "_LLM analysis skipped (no provider configured) — raw collected data below._",
             ""]
    lines.append("### Sources")
    lines.append("")
    if result_rows:
        lines.append("| # | Engine | Title | URL | Score | Corr |")
        lines.append("|---|--------|-------|-----|-------|------|")
        for index, row in enumerate(result_rows, start=1):
            title = (row.get("title") or "")[:80].replace("|", "/")
            lines.append("| %d | %s | %s | %s | %.2f | %s |"
                         % (index, row.get("engine", "?"), title,
                            row.get("url", ""), row.get("score", 0.0),
                            row.get("corroboration", 1)))
    else:
        lines.append("_No search results collected._")
    lines.append("")

    if scraped:
        lines.append("### Scraped excerpts")
        lines.append("")
        for url, text in scraped.items():
            excerpt = re.sub(r"\s+", " ", text)[:400].strip()
            lines.append("**%s**" % url)
            lines.append("")
            lines.append("> %s" % excerpt + ("..." if len(text) > 400 else ""))
            lines.append("")
    if errors:
        lines.append("### Errors")
        lines.append("")
        for error in errors:
            lines.append("- %s" % error)
        lines.append("")
    return "\n".join(lines)


def run_pipeline(query: str,
                 mode: str = "threat_intel",
                 max_results: int = 0,
                 scrape: int = 0,
                 custom: Optional[str] = None,
                 out: Optional[str] = None,
                 engines: Optional[List[str]] = None,
                 clear_cache_first: bool = False,
                 log: Callable[[str], None] = print) -> Dict[str, object]:
    """Run the complete investigation and return the report plus collected data."""
    query = (query or "").strip()
    if not query:
        return {"ok": False, "error": "empty query"}

    config = mode_config(mode)
    max_results = max_results or config["max_results"]
    scrape = scrape or config["scrape"]
    errors: List[str] = []

    if clear_cache_first:
        removed = clear_cache()
        log("[0] Cache cleared (%d entries)" % removed)

    if not llm_available():
        log("[!] No LLM provider configured (%s) — running offline fallbacks"
            % provider_summary())
    else:
        log("[i] LLM provider: %s" % provider_summary())

    log("[1] Verifying Tor…")
    tor_status = check_tor()
    if not tor_status.get("tor_active"):
        message = tor_status.get("error") or "Tor is not active"
        return {"ok": False, "error": message, "tor": tor_status}
    log("    Tor active — exit IP %s" % tor_status.get("exit_ip"))

    log("[2] Checking search engines…")
    engine_report = check_search_engines(cached_minutes=15)
    alive = [row["name"] for row in engine_report["results"] if row["status"] == "up"]
    log("    %d/%d engines alive%s" % (engine_report["alive"], engine_report["total"],
                                      " (cached)" if engine_report.get("cached") else ""))
    if not alive:
        errors.append("no engines reachable — using the configured default set")
        selected_name = None
    else:
        selected_name = engines or alive

    log("[3] Refining query…")
    refined = refine_query(query)
    if refined != query:
        log("    “%s” → “%s”" % (query, refined))
    else:
        log("    keeping query as-is")

    log("[4] Searching %d engine(s)…"
        % (len(selected_name) if selected_name else len(engine_report["results"])))
    search_report = search_detailed(refined, engines=selected_name,
                                   use_cache=not clear_cache_first)
    if not search_report.get("ok"):
        return {"ok": False, "error": search_report.get("error"), "tor": tor_status}
    for name, info in sorted(search_report["per_engine"].items()):
        if info["status"] != "up":
            errors.append("%s: %s" % (name, info.get("error") or "down"))
    log("    %d unique results in %ss"
        % (search_report["count"], search_report.get("elapsed_s", "?")))

    log("[5] Filtering to the top %d…" % max_results)
    ranked = filter_results(refined, search_report["results"], keep=max_results)
    ranked = score_results(refined, ranked)
    log("    %d results kept" % len(ranked))

    scraped: Dict[str, str] = {}
    if scrape > 0 and ranked:
        log("[6] Scraping %d page(s)…" % min(scrape, len(ranked)))
        targets = [row["url"] for row in ranked[:scrape]]

        def _page(result: dict) -> None:
            if result.get("ok"):
                log("    ✓ %s" % result.get("url"))
            else:
                log("    ✗ %s — %s" % (result.get("url"), result.get("error")))

        scraped = scrape_all(targets, on_page=_page)
    else:
        log("[6] Scraping skipped")

    provider_ready = llm_available()
    iocs = extract_iocs(scraped)
    indicator_count = ioc_total(iocs)
    if indicator_count:
        log("[7a] Extracted %d indicators from scraped content" % indicator_count)
    secret_hits = find_secret_hits(scraped)
    if secret_hits:
        log("     ⚠ %d secret/credential pattern(s) detected — masked in the report"
            % len(secret_hits))

    analysis = ""
    if provider_ready:
        log("[7] Running LLM analysis (%s)…" % mode)
        sections = ["### Query: %s" % refined, ""]
        for url, text in scraped.items():
            sections.append("#### Source: %s" % url)
            sections.append(text)
            sections.append("")
        combined = "\n".join(sections)
        try:
            analysis = ask(refined, combined, mode=mode, custom=custom,
                           sources=ranked)
        except LLMError as exc:
            errors.append("LLM analysis failed: %s" % exc)
            log("    ✗ %s" % exc)
            analysis = _fallback_report(query, mode, ranked, scraped, errors)
    else:
        log("[7] LLM analysis skipped — building offline report")
        analysis = _fallback_report(query, mode, ranked, scraped, errors)

    header = [
        "# Xikin investigation report",
        "",
        "- **Query:** %s" % query,
        "- **Refined query:** `%s`" % refined,
        "- **Mode:** %s (%s)" % (mode, config["label"]),
        "- **Generated:** %s" % utc_now_iso(),
        "- **Tool:** xikin %s — LLM: %s"
        % (__version__, provider_summary() if llm_available() else "none (offline fallback)"),
        "- **Tor exit IP:** %s" % tor_status.get("exit_ip"),
        "- **Engines queried:** %s" % ", ".join(search_report.get("engines", [])),
        "- **Results collected:** %d (scraped: %d)"
        % (len(ranked), len(scraped)),
        "- **Indicators extracted:** %d (deterministic, no LLM)" % indicator_count,
        "",
        analysis,
        "",
        render_iocs(iocs, redact=True),
        "---",
        "",
        "_%s_" % SAFETY_NOTE,
        "_For lawful OSINT, threat intelligence and security research only._",
        "",
    ]
    report = "\n".join(header)

    path = None
    if out:
        path = os.path.abspath(out)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(report)
        log("[8] Report written to %s" % path)

    return {
        "ok": True,
        "query": query,
        "refined_query": refined,
        "mode": mode,
        "tor": tor_status,
        "engines": search_report.get("engines", []),
        "results": ranked,
        "scraped": list(scraped.keys()),
        "iocs": iocs,
        "indicator_count": indicator_count,
        "report": report,
        "path": path,
        "errors": errors,
    }
