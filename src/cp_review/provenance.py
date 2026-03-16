"""Run provenance metadata helpers."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cp_review import __version__
from cp_review.config import AppConfig


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_artifact_inventory(artifacts: dict[str, Path]) -> list[dict[str, str]]:
    """Return hashed artifact metadata for files that exist on disk."""
    artifact_items: list[dict[str, str]] = []
    for name, artifact_path in artifacts.items():
        file_hash = sha256_file(artifact_path)
        if file_hash is None:
            continue
        artifact_items.append(
            {
                "name": name,
                "path": str(artifact_path.resolve()),
                "sha256": file_hash,
            }
        )
    artifact_items.sort(key=lambda item: item["name"])
    return artifact_items


def _git_value(args: list[str]) -> str | None:
    repo_root = Path(__file__).resolve().parents[2]
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            check=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    value = result.stdout.strip()
    return value or None


def build_provenance_record(
    *,
    command: str,
    run_id: str,
    settings: AppConfig,
    artifacts: dict[str, Path],
) -> dict[str, Any]:
    """Create a serializable provenance document for one run command."""
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "tool": {
            "name": "cp-review",
            "version": __version__,
        },
        "execution": {
            "command": command,
            "run_id": run_id,
            "python_version": platform.python_version(),
            "source_host": settings.management.host,
        },
        "source_control": {
            "git_commit": _git_value(["rev-parse", "HEAD"]),
            "git_branch": _git_value(["rev-parse", "--abbrev-ref", "HEAD"]),
        },
        "config": settings.sanitized_summary(),
        "artifacts": build_artifact_inventory(artifacts),
    }


def write_provenance_file(
    path: Path,
    *,
    command: str,
    run_id: str,
    settings: AppConfig,
    artifacts: dict[str, Path],
) -> Path:
    """Write provenance metadata JSON to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_provenance_record(
        command=command,
        run_id=run_id,
        settings=settings,
        artifacts=artifacts,
    )
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
