"""Validation helpers for completed run artifacts."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from cp_review.normalize.dataset import load_dataset
from cp_review.provenance import sha256_file

STRICT_WARNING_CODES = {"OBJECT_LOOKUP_FAILED", "LOG_QUERY_FAILED", "NO_ACCESS_LAYERS"}
EXPECTED_ARTIFACTS_BY_COMMAND: dict[str, set[str]] = {
    "collect": {"dataset_json", "metrics_json", "provenance_json"},
    "analyze": {
        "dataset_json",
        "findings_json",
        "metrics_json",
        "provenance_json",
        "review_queue_json",
        "review_queue_csv",
        "review_queue_html",
        "review_state_yaml",
    },
    "report": {
        "dataset_json",
        "findings_json",
        "report_html",
        "metrics_json",
        "provenance_json",
        "review_queue_json",
        "review_queue_csv",
        "review_queue_html",
        "review_state_yaml",
    },
    "full-run": {
        "dataset_json",
        "findings_json",
        "report_html",
        "metrics_json",
        "provenance_json",
        "review_queue_json",
        "review_queue_csv",
        "review_queue_html",
        "review_state_yaml",
    },
    "compare": {"previous_findings_json", "current_findings_json", "drift_json", "metrics_json", "provenance_json"},
}
STRICT_ARTIFACTS_BY_COMMAND: dict[str, set[str]] = {
    "analyze": {"report_html"},
    "report": set(),
    "full-run": set(),
    "compare": {"drift_summary_html"},
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


def _check(name: str, ok: bool, details: str) -> dict[str, str]:
    return {"name": name, "status": _status(ok), "details": details}


def load_manifest(path: Path) -> dict[str, Any]:
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"Manifest is not a JSON object: {path}")
    return payload


def _validate_required_artifacts(
    checks: list[dict[str, str]],
    command: str,
    artifacts: dict[str, dict[str, str]],
    *,
    strict: bool,
) -> None:
    expected_artifacts = set(EXPECTED_ARTIFACTS_BY_COMMAND.get(command, set()))
    if strict:
        expected_artifacts.update(STRICT_ARTIFACTS_BY_COMMAND.get(command, set()))
    missing_artifacts = sorted(expected_artifacts - artifacts.keys())
    checks.append(
        _check(
            "required_artifacts_listed",
            not missing_artifacts,
            ", ".join(missing_artifacts) if missing_artifacts else f"{len(expected_artifacts)} required artifacts listed",
        )
    )


def _validate_artifact_files(checks: list[dict[str, str]], artifacts: dict[str, dict[str, str]]) -> None:
    for artifact_name, artifact in sorted(artifacts.items()):
        artifact_path = Path(artifact["path"])
        exists = artifact_path.exists()
        checks.append(_check(f"artifact_exists:{artifact_name}", exists, str(artifact_path)))
        if not exists:
            continue
        expected_hash = artifact.get("sha256")
        actual_hash = sha256_file(artifact_path)
        checks.append(_check(f"artifact_hash:{artifact_name}", bool(actual_hash and expected_hash == actual_hash), str(artifact_path)))


def _validate_dataset_summary(
    checks: list[dict[str, str]],
    manifest: dict[str, Any],
    artifacts: dict[str, dict[str, str]],
    *,
    strict: bool,
) -> None:
    summary = manifest.get("summary", {})
    run_id = str(manifest.get("run_id", "unknown"))
    manifest_warnings = manifest.get("warnings", [])
    dataset_artifact = artifacts.get("dataset_json")
    if not dataset_artifact:
        return

    dataset = load_dataset(Path(dataset_artifact["path"]))
    checks.append(_check("dataset_run_id", dataset.run_id == run_id, f"dataset.run_id={dataset.run_id}"))
    if not isinstance(summary, dict):
        return

    rules_count = summary.get("rules_count")
    if rules_count is not None:
        checks.append(_check("summary_rules_count", int(rules_count) == len(dataset.rules), f"summary={rules_count} dataset={len(dataset.rules)}"))

    warnings_count = summary.get("warnings_count")
    if warnings_count is not None:
        checks.append(_check("summary_warnings_count", int(warnings_count) == len(dataset.warnings), f"summary={warnings_count} dataset={len(dataset.warnings)}"))
        if isinstance(manifest_warnings, list):
            checks.append(
                _check(
                    "manifest_warnings_count",
                    int(warnings_count) == len(manifest_warnings),
                    f"summary={warnings_count} manifest={len(manifest_warnings)}",
                )
            )

    if strict:
        strict_warnings = [warning for warning in dataset.warnings if warning.code in STRICT_WARNING_CODES]
        checks.append(
            _check(
                "strict_structural_warnings",
                not strict_warnings,
                ", ".join(sorted({warning.code for warning in strict_warnings})) if strict_warnings else "none",
            )
        )


def _validate_findings_and_queue(
    checks: list[dict[str, str]],
    manifest: dict[str, Any],
    artifacts: dict[str, dict[str, str]],
) -> None:
    summary = manifest.get("summary", {})
    if not isinstance(summary, dict):
        return

    findings_artifact_name = "findings_json" if "findings_json" in artifacts else "current_findings_json"
    findings_artifact = artifacts.get(findings_artifact_name)
    if findings_artifact:
        findings_payload = _load_json(Path(findings_artifact["path"]))
        findings_count = summary.get("findings_count") or summary.get("current_count")
        if findings_count is not None and isinstance(findings_payload, list):
            checks.append(
                _check(
                    "summary_findings_count",
                    int(findings_count) == len(findings_payload),
                    f"summary={findings_count} findings={len(findings_payload)}",
                )
            )

    queue_artifact = artifacts.get("review_queue_json")
    if queue_artifact:
        queue_payload = _load_json(Path(queue_artifact["path"]))
        if isinstance(queue_payload, list):
            queue_count = summary.get("review_queue_count")
            if queue_count is not None:
                checks.append(
                    _check(
                        "summary_review_queue_count",
                        int(queue_count) == len(queue_payload),
                        f"summary={queue_count} queue={len(queue_payload)}",
                    )
                )
            action_counts = summary.get("action_counts")
            if isinstance(action_counts, dict):
                queue_actions = Counter(str(item.get("action_type", "")) for item in queue_payload if isinstance(item, dict))
                checks.append(
                    _check(
                        "summary_action_counts",
                        dict(sorted(action_counts.items())) == dict(sorted(queue_actions.items())),
                        f"summary={dict(sorted(action_counts.items()))} queue={dict(sorted(queue_actions.items()))}",
                    )
                )


def _validate_metrics(checks: list[dict[str, str]], manifest: dict[str, Any], artifacts: dict[str, dict[str, str]]) -> None:
    command = str(manifest.get("command", "unknown"))
    run_id = str(manifest.get("run_id", "unknown"))
    metrics_artifact = artifacts.get("metrics_json")
    if not metrics_artifact:
        return
    metrics = _load_json(Path(metrics_artifact["path"]))
    checks.append(_check("metrics_command", metrics.get("command") == command, f"metrics.command={metrics.get('command')}"))
    checks.append(_check("metrics_run_id", metrics.get("run_id") == run_id, f"metrics.run_id={metrics.get('run_id')}"))


def _validate_html_artifacts(checks: list[dict[str, str]], artifacts: dict[str, dict[str, str]], *, strict: bool) -> None:
    if not strict:
        return
    for name in ("report_html", "review_queue_html", "drift_summary_html"):
        artifact = artifacts.get(name)
        if not artifact:
            continue
        html = Path(artifact["path"]).read_text(encoding="utf-8")
        checks.append(_check(f"html_document:{name}", "<html" in html.lower(), artifact["path"]))


def validate_run_manifest(path: Path, *, strict: bool = False) -> dict[str, Any]:
    """Validate a run manifest and the artifacts it references."""
    manifest = load_manifest(path)
    command = str(manifest.get("command", "unknown"))
    run_id = str(manifest.get("run_id", "unknown"))
    checks: list[dict[str, str]] = []

    checks.append(_check("manifest_schema", isinstance(manifest.get("schema_version"), int), f"schema_version={manifest.get('schema_version')}"))
    checks.append(_check("manifest_status", manifest.get("status") == "completed", f"status={manifest.get('status')}"))
    checks.append(_check("manifest_command", command in EXPECTED_ARTIFACTS_BY_COMMAND, command))

    artifacts = _artifact_map(manifest)
    _validate_required_artifacts(checks, command, artifacts, strict=strict)
    _validate_artifact_files(checks, artifacts)
    _validate_dataset_summary(checks, manifest, artifacts, strict=strict)
    _validate_findings_and_queue(checks, manifest, artifacts)
    _validate_metrics(checks, manifest, artifacts)
    _validate_html_artifacts(checks, artifacts, strict=strict)

    has_fail = any(item["status"] == "fail" for item in checks)
    return {
        "summary": "fail" if has_fail else "ok",
        "command": command,
        "run_id": run_id,
        "strict": strict,
        "manifest_path": str(path.resolve()),
        "checks": checks,
    }
