"""Run the Xikin web platform: ``python -m xikin.web``."""
from __future__ import annotations

from ..config import settings
from .security import is_loopback


def main() -> None:
    import uvicorn

    if not is_loopback(settings.web_host) and not settings.web_token:
        raise SystemExit(
            "Refusing to start: XIKIN_WEB_HOST=%s is not loopback and "
            "XIKIN_WEB_TOKEN is not set. Set a token or bind 127.0.0.1."
            % settings.web_host)
    print("Xikin web platform on http://%s:%d"
          % (settings.web_host, settings.web_port))
    if not settings.web_token:
        print("[!] Authentication disabled — set XIKIN_WEB_TOKEN to require login.")
    uvicorn.run("xikin.web.app:create_app", factory=True,
                host=settings.web_host, port=settings.web_port,
                log_level="info")


if __name__ == "__main__":
    main()
