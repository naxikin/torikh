"""Xikin — Tor / dark-web OSINT toolkit for analysts and AI agents."""
from __future__ import annotations

import warnings

warnings.filterwarnings("ignore", message=".*urllib3 v2 only supports OpenSSL.*")

__version__ = "0.1.0"

from .config import settings  # noqa: F401
from .doctor import run_all as doctor  # noqa: F401
from .engines import ENGINES, check_search_engines  # noqa: F401
from .evidence import EvidenceLog  # noqa: F401
from .fetch import fetch, scrape_all  # noqa: F401
from .iocs import extract as extract_iocs  # noqa: F401
from .llm import ask, filter_results, llm_available, refine_query  # noqa: F401
from .pipeline import run_pipeline  # noqa: F401
from .search import search, search_detailed  # noqa: F401
from .tor import check_tor, renew_identity  # noqa: F401

__all__ = [
    "__version__",
    "settings",
    "ENGINES",
    "EvidenceLog",
    "doctor",
    "extract_iocs",
    "check_tor",
    "renew_identity",
    "check_search_engines",
    "search",
    "search_detailed",
    "fetch",
    "scrape_all",
    "ask",
    "refine_query",
    "filter_results",
    "llm_available",
    "run_pipeline",
]
