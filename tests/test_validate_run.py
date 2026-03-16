from __future__ import annotations

import json
from pathlib import Path

from pydantic import SecretStr

from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig
from cp_review.run_manifest import write_run_manifest
from cp_review.validate_run import validate_run_manifest


def _settings(tmp_path: Path) -> AppConfig:
    return AppConfig(
        management=ManagementConfig(
            host="mgmt.example.local",
            username=SecretStr("user"),
            password=SecretStr("pass"),
        ),
        collection=CollectionConfig(output_dir=tmp_path / "output"),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )


def _dataset_payload(run_id: str) -> dict[str, object]:
    return {
        "generated_at": "2026-03-16T00:00:00Z",
        "run_id": run_id,
        "source_host": "mgmt.example.local",
        "packages": ["Standard"],
        "rules": [],
        "log_evidence": {},
        "warnings": [],
        "raw_dir": "/tmp/raw",
    }


def test_validate_run_manifest_passes_for_consistent_analyze_run(tmp_path: Path):
    settings = _settings(tmp_path)
    reports_dir = tmp_path / "output" / "reports" / "run-123"
    reports_dir.mkdir(parents=True)
    dataset_path = tmp_path / "output" / "normalized" / "run-123" / "dataset.json"
    dataset_path.parent.mkdir(parents=True)
    dataset_path.write_text(json.dumps(_dataset_payload("run-123")), encoding="utf-8")
    findings_path = reports_dir / "findings.json"
    findings_path.write_text("[]", encoding="utf-8")
    metrics_path = reports_dir / "metrics.json"
    metrics_path.write_text(json.dumps({"command": "analyze", "run_id": "run-123"}), encoding="utf-8")
    provenance_path = reports_dir / "provenance.json"
    provenance_path.write_text("{}", encoding="utf-8")
    manifest_path = reports_dir / "run-manifest.json"

    write_run_manifest(
        manifest_path,
        command="analyze",
        run_id="run-123",
        settings=settings,
        artifacts={
            "dataset_json": dataset_path,
            "findings_json": findings_path,
            "metrics_json": metrics_path,
            "provenance_json": provenance_path,
        },
        summary={"findings_count": 0, "rules_count": 0, "warnings_count": 0},
    )

    report = validate_run_manifest(manifest_path)

    assert report["summary"] == "ok"


def test_validate_run_manifest_fails_on_hash_mismatch(tmp_path: Path):
    settings = _settings(tmp_path)
    reports_dir = tmp_path / "output" / "reports" / "run-123"
    reports_dir.mkdir(parents=True)
    dataset_path = tmp_path / "output" / "normalized" / "run-123" / "dataset.json"
    dataset_path.parent.mkdir(parents=True)
    dataset_path.write_text(json.dumps(_dataset_payload("run-123")), encoding="utf-8")
    findings_path = reports_dir / "findings.json"
    findings_path.write_text("[]", encoding="utf-8")
    metrics_path = reports_dir / "metrics.json"
    metrics_path.write_text(json.dumps({"command": "analyze", "run_id": "run-123"}), encoding="utf-8")
    provenance_path = reports_dir / "provenance.json"
    provenance_path.write_text("{}", encoding="utf-8")
    manifest_path = reports_dir / "run-manifest.json"

    write_run_manifest(
        manifest_path,
        command="analyze",
        run_id="run-123",
        settings=settings,
        artifacts={
            "dataset_json": dataset_path,
            "findings_json": findings_path,
            "metrics_json": metrics_path,
            "provenance_json": provenance_path,
        },
        summary={"findings_count": 0, "rules_count": 0, "warnings_count": 0},
    )
    findings_path.write_text('[{"changed": true}]', encoding="utf-8")

    report = validate_run_manifest(manifest_path)

    assert report["summary"] == "fail"
    assert any(check["name"] == "artifact_hash:findings_json" and check["status"] == "fail" for check in report["checks"])
