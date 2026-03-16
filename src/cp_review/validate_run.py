"""Validation helpers for completed run artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cp_review.normalize.dataset import load_dataset
from cp_review.provenance import sha256_file

EXPECTED_ARTIFACTS_BY_COMMAND: dict[str, set[str]] = {
    "collect": {"dataset_json", "metrics_json", "provenance_json"},
    "analyze": {"dataset_json", "findings_json", "metrics_json", "provenance_json"},
    "report": {"dataset_json", "findings_json", "report_html", "metrics_json", "provenance_json"},
    "full-run": {"dataset_json", "findings_json", "metrics_json", "provenance_json"},
    "compare": {"previous_findings_json", "current_findings_json", "drift_json", "metrics_json", "provenance_json"},
}


def _status(ok: bool) -> str:
    return "ok" if ok else "fail"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _artifact_map(manifest: dict[str, Any]) -> dict[str, dict[str, str]]:
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        return {}
    result: dict[str, dict[str, str]] = {}
    for item in artifacts:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            result[item["name"]] = {str(key): str(value) for key, value in item.items() if isinstance(value, str)}
    return result


def load_manifest(path: Path) -> dict[str, Any]:
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"Manifest is not a JSON object: {path}")
    return payload


def validate_run_manifest(path: Path) -> dict[str, Any]:
    """Validate a run manifest and the artifacts it references."""
    manifest = load_manifest(path)
    command = str(manifest.get("command", "unknown"))
    run_id = str(manifest.get("run_id", "unknown"))
    summary = manifest.get("summary", {})
    manifest_warnings = manifest.get("warnings", [])
    checks: list[dict[str, str]] = []

    checks.append(
        {
            "name": "manifest_schema",
            "status": _status(isinstance(manifest.get("schema_version"), int)),
            "details": f"schema_version={manifest.get('schema_version')}",
        }
    )
    checks.append(
        {
            "name": "manifest_status",
            "status": _status(manifest.get("status") == "completed"),
            "details": f"status={manifest.get('status')}",
        }
    )
    checks.append(
        {
            "name": "manifest_command",
            "status": _status(command in EXPECTED_ARTIFACTS_BY_COMMAND),
            "details": command,
        }
    )

    artifacts = _artifact_map(manifest)
    expected_artifacts = EXPECTED_ARTIFACTS_BY_COMMAND.get(command, set())
    missing_artifacts = sorted(expected_artifacts - artifacts.keys())
    checks.append(
        {
            "name": "required_artifacts_listed",
            "status": _status(not missing_artifacts),
            "details": ", ".join(missing_artifacts) if missing_artifacts else f"{len(expected_artifacts)} required artifacts listed",
        }
    )

    for artifact_name, artifact in sorted(artifacts.items()):
        artifact_path = Path(artifact["path"])
        exists = artifact_path.exists()
        checks.append(
            {
                "name": f"artifact_exists:{artifact_name}",
                "status": _status(exists),
                "details": str(artifact_path),
            }
        )
        if not exists:
            continue
        expected_hash = artifact.get("sha256")
        actual_hash = sha256_file(artifact_path)
        checks.append(
            {
                "name": f"artifact_hash:{artifact_name}",
                "status": _status(bool(actual_hash and expected_hash == actual_hash)),
                "details": str(artifact_path),
            }
        )

    dataset_artifact = artifacts.get("dataset_json")
    if dataset_artifact:
        dataset = load_dataset(Path(dataset_artifact["path"]))
        checks.append(
            {
                "name": "dataset_run_id",
                "status": _status(dataset.run_id == run_id),
                "details": f"dataset.run_id={dataset.run_id}",
            }
        )
        if isinstance(summary, dict):
            rules_count = summary.get("rules_count")
            warnings_count = summary.get("warnings_count")
            if rules_count is not None:
                checks.append(
                    {
                        "name": "summary_rules_count",
                        "status": _status(int(rules_count) == len(dataset.rules)),
                        "details": f"summary={rules_count} dataset={len(dataset.rules)}",
                    }
                )
            if warnings_count is not None:
                checks.append(
                    {
                        "name": "summary_warnings_count",
                        "status": _status(int(warnings_count) == len(dataset.warnings)),
                        "details": f"summary={warnings_count} dataset={len(dataset.warnings)}",
                    }
                )
                if isinstance(manifest_warnings, list):
                    checks.append(
                        {
                            "name": "manifest_warnings_count",
                            "status": _status(int(warnings_count) == len(manifest_warnings)),
                            "details": f"summary={warnings_count} manifest={len(manifest_warnings)}",
                        }
                    )

    findings_artifact_name = "findings_json" if "findings_json" in artifacts else "current_findings_json"
    findings_artifact = artifacts.get(findings_artifact_name)
    if findings_artifact and isinstance(summary, dict):
        findings_payload = _load_json(Path(findings_artifact["path"]))
        findings_count = summary.get("findings_count") or summary.get("current_count")
        if findings_count is not None and isinstance(findings_payload, list):
            checks.append(
                {
                    "name": "summary_findings_count",
                    "status": _status(int(findings_count) == len(findings_payload)),
                    "details": f"summary={findings_count} findings={len(findings_payload)}",
                }
            )

    metrics_artifact = artifacts.get("metrics_json")
    if metrics_artifact:
        metrics = _load_json(Path(metrics_artifact["path"]))
        checks.append(
            {
                "name": "metrics_command",
                "status": _status(metrics.get("command") == command),
                "details": f"metrics.command={metrics.get('command')}",
            }
        )
        checks.append(
            {
                "name": "metrics_run_id",
                "status": _status(metrics.get("run_id") == run_id),
                "details": f"metrics.run_id={metrics.get('run_id')}",
            }
        )

    has_fail = any(item["status"] == "fail" for item in checks)
    return {
        "summary": "fail" if has_fail else "ok",
        "command": command,
        "run_id": run_id,
        "manifest_path": str(path.resolve()),
        "checks": checks,
    }
