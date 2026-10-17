"""Xikin web platform — FastAPI app served by ``python -m xikin.web``."""
from __future__ import annotations

from .app import create_app  # noqa: F401

__all__ = ["create_app"]
