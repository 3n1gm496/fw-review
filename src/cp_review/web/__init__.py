"""Web server entrypoints for fw-review."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, cast
from wsgiref.simple_server import make_server

from cp_review.web.app import WebApplication


def serve_web_app(settings, web_config, *, web_config_path: Path) -> None:
    """Start the local remediation cockpit server."""
    app = WebApplication(settings, web_config, web_config_path=web_config_path)
    wsgi_app = cast(Callable[[dict[str, Any], Any], Iterable[bytes]], app)
    with make_server(web_config.host, web_config.port, wsgi_app) as server:
        print(f"fw-review web cockpit listening on http://{web_config.host}:{web_config.port}")
        server.serve_forever()
