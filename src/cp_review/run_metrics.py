"""Structured run metrics helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cp_review.config import AppConfig


def build_run_metrics(
    *,
    command: str,
    run_id: str,
    settings: AppConfig,
    duration_seconds: float,
    api_call_count: int = 0,
    api_commands: dict[str, int] | None = None,
    findings_count: int | None = None,
    rules_count: int | None = None,
    warnings_count: int | None = None,
) -> dict[str, Any]:
    """Build a serializable metrics record for one CLI run."""
    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "command": command,
        "run_id": run_id,
        "source_host": settings.management.host,
        "duration_seconds": round(duration_seconds, 3),
        "api_call_count": api_call_count,
        "api_commands": dict(sorted((api_commands or {}).items())),
    }
    if findings_count is not None:
        payload["findings_count"] = findings_count
    if rules_count is not None:
        payload["rules_count"] = rules_count
    if warnings_count is not None:
        payload["warnings_count"] = warnings_count
    return payload


def write_run_metrics(path: Path, metrics: dict[str, Any]) -> Path:
    """Persist run metrics as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    return path
