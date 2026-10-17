"""Configuration — loaded from environment variables and an optional .env file."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"
ENGINES_FILE = ROOT / "engines.json"


def _parse_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


def load_env(path: Optional[Path] = None) -> None:
    env_path = path or ENV_FILE
    try:
        from dotenv import load_dotenv

        load_dotenv(env_path)
    except Exception:
        _parse_env_file(env_path)


def _str(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


def _int(name: str, default: int) -> int:
    try:
        return int(_str(name, str(default)) or default)
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(_str(name, str(default)) or default)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    # Tor
    tor_socks_host: str = "127.0.0.1"
    tor_socks_port: int = 9050
    tor_control_host: str = "127.0.0.1"
    tor_control_port: int = 9051
    tor_control_password: Optional[str] = None
    tor_data_dir: Optional[str] = None
    tor_timeout: int = 45
    tor_connect_timeout: int = 15

    # Behaviour
    max_content_chars: int = 8000
    search_workers: int = 8
    scrape_workers: int = 5
    engine_max_results: int = 40
    fetch_cache_ttl: int = 600
    search_cache_ttl: int = 1800
    engine_cache_ttl: int = 3600
    db_path: str = ""
    isolate_circuits: bool = True
    evidence_enabled: bool = True
    evidence_path: str = ""

    # LLM
    llm_provider: str = "openai"
    llm_timeout: int = 120
    llm_max_chars: int = 24000
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com"
    anthropic_api_key: Optional[str] = None
    anthropic_model: str = "claude-sonnet-4-5"
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.5-flash"
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2"
    llamacpp_base_url: str = "http://127.0.0.1:8080"
    llamacpp_model: str = "local-model"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            tor_socks_host=_str("TOR_SOCKS_HOST", "127.0.0.1"),
            tor_socks_port=_int("TOR_SOCKS_PORT", 9050),
            tor_control_host=_str("TOR_CONTROL_HOST", "127.0.0.1"),
            tor_control_port=_int("TOR_CONTROL_PORT", 9051),
            tor_control_password=_str("TOR_CONTROL_PASSWORD"),
            tor_data_dir=_str("TOR_DATA_DIR"),
            tor_timeout=_int("TOR_TIMEOUT", 45),
            tor_connect_timeout=_int("TOR_CONNECT_TIMEOUT", 15),
            max_content_chars=_int("XIKIN_MAX_CHARS", 8000),
            search_workers=_int("XIKIN_SEARCH_WORKERS", 8),
            scrape_workers=_int("XIKIN_SCRAPE_WORKERS", 5),
            engine_max_results=_int("XIKIN_ENGINE_MAX_RESULTS", 40),
            fetch_cache_ttl=_int("XIKIN_FETCH_CACHE_TTL", 600),
            search_cache_ttl=_int("XIKIN_SEARCH_CACHE_TTL", 1800),
            engine_cache_ttl=_int("XIKIN_ENGINE_CACHE_TTL", 3600),
            db_path=_str("XIKIN_DB_PATH", str(Path.home() / ".xikin" / "xikin.db")),
            isolate_circuits=_str("XIKIN_ISOLATE", "1") not in ("0", "false", "off", "no"),
            evidence_enabled=_str("XIKIN_EVIDENCE", "1") not in ("0", "false", "off", "no"),
            evidence_path=_str("XIKIN_EVIDENCE_LOG",
                               str(Path.home() / ".xikin" / "evidence.jsonl")),
            llm_provider=(_str("LLM_PROVIDER", "openai") or "openai").lower(),
            llm_timeout=_int("XIKIN_LLM_TIMEOUT", 120),
            llm_max_chars=_int("XIKIN_LLM_MAX_CHARS", 24000),
            openai_api_key=_str("OPENAI_API_KEY"),
            openai_model=_str("OPENAI_MODEL", "gpt-4o-mini"),
            openai_base_url=_str("OPENAI_BASE_URL", "https://api.openai.com"),
            anthropic_api_key=_str("ANTHROPIC_API_KEY"),
            anthropic_model=_str("ANTHROPIC_MODEL", "claude-sonnet-4-5"),
            gemini_api_key=_str("GEMINI_API_KEY"),
            gemini_model=_str("GEMINI_MODEL", "gemini-2.5-flash"),
            ollama_base_url=_str("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
            ollama_model=_str("OLLAMA_MODEL", "llama3.2"),
            llamacpp_base_url=_str("LLAMACPP_BASE_URL", "http://127.0.0.1:8080"),
            llamacpp_model=_str("LLAMACPP_MODEL", "local-model"),
        )


load_env()
settings = Settings.from_env()
