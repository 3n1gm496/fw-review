"""Web application configuration helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


class WebConfig(BaseModel):
    """Runtime settings for the local-first remediation cockpit."""

    host: str = "127.0.0.1"
    port: int = 8765
    app_dir: Path
    db_path: Path
    auto_sync_on_start: bool = True
    launch_strict_validate: bool = True
    shared_mode: bool = True
    session_cookie_name: str = "fw_review_session"
    session_ttl_hours: int = 12

    @classmethod
    def defaults(cls, *, output_dir: Path) -> WebConfig:
        app_dir = output_dir / "web"
        return cls(app_dir=app_dir, db_path=app_dir / "fw-review-web.db")


DEFAULT_WEB_TEMPLATE = """web:\n  host: \"127.0.0.1\"\n  port: 8765\n  app_dir: \"./output/web\"\n  db_path: \"./output/web/fw-review-web.db\"\n  auto_sync_on_start: true\n  launch_strict_validate: true\n  shared_mode: true\n  session_cookie_name: \"fw_review_session\"\n  session_ttl_hours: 12\n"""


def load_web_config(settings, *, config_path: Path | None = None) -> WebConfig:
    """Load web config from YAML or synthesize defaults from app settings."""
    defaults = WebConfig.defaults(output_dir=settings.collection.output_dir)
    if config_path is None:
        config_path = settings.collection.output_dir.parent / "config" / "web.yaml"
    if not config_path.exists():
        return defaults

    payload = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    web_raw = payload.get("web", payload) if isinstance(payload, dict) else {}
    if not isinstance(web_raw, dict):
        return defaults

    merged: dict[str, Any] = defaults.model_dump(mode="python")
    merged.update(web_raw)
    config = WebConfig.model_validate(merged)
    base_dir = config_path.parent.resolve()
    if not config.app_dir.is_absolute():
        config.app_dir = (base_dir / config.app_dir).resolve()
    if not config.db_path.is_absolute():
        config.db_path = (base_dir / config.db_path).resolve()
    return config


def write_web_config(path: Path, config: WebConfig, *, force: bool = False) -> Path:
    """Write a portable web config template."""
    if path.exists() and not force:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "web": {
            "host": config.host,
            "port": config.port,
            "app_dir": str(config.app_dir),
            "db_path": str(config.db_path),
            "auto_sync_on_start": config.auto_sync_on_start,
            "launch_strict_validate": config.launch_strict_validate,
            "shared_mode": config.shared_mode,
            "session_cookie_name": config.session_cookie_name,
            "session_ttl_hours": config.session_ttl_hours,
        }
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path
