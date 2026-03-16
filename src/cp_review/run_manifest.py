"""Run manifest helpers for artifact completeness and troubleshooting."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cp_review.config import AppConfig
from cp_review.models import DatasetWarning
from cp_review.provenance import build_artifact_inventory


def _serialize_warnings(warnings: Sequence[DatasetWarning | dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not warnings:
        return []
    payload: list[dict[str, Any]] = []
    for item in warnings:
        warning = item.model_dump(mode="json") if isinstance(item, DatasetWarning) else dict(item)
        payload.append(warning)
    payload.sort(
        key=lambda item: (
            str(item.get("code", "")),
            str(item.get("package_name", "")),
            str(item.get("layer_name", "")),
            str(item.get("rule_uid", "")),
            str(item.get("object_uid", "")),
            str(item.get("message", "")),
        )
    )
    return payload


def build_run_manifest(
    *,
    command: str,
    run_id: str,
    settings: AppConfig,
    artifacts: dict[str, Path],
    status: str = "completed",
    summary: dict[str, Any] | None = None,
    warnings: Sequence[DatasetWarning | dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create a serializable manifest for one completed command run."""
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "status": status,
        "command": command,
        "run_id": run_id,
        "source_host": settings.management.host,
        "artifacts": build_artifact_inventory(artifacts),
        "summary": dict(sorted((summary or {}).items())),
        "warnings": _serialize_warnings(warnings),
    }


def write_run_manifest(
    path: Path,
    *,
    command: str,
    run_id: str,
    settings: AppConfig,
    artifacts: dict[str, Path],
    status: str = "completed",
    summary: dict[str, Any] | None = None,
    warnings: Sequence[DatasetWarning | dict[str, Any]] | None = None,
) -> Path:
    """Write a run manifest to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_run_manifest(
        command=command,
        run_id=run_id,
        settings=settings,
        artifacts=artifacts,
        status=status,
        summary=summary,
        warnings=warnings,
    )
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
