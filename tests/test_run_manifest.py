from __future__ import annotations

import json
from pathlib import Path

from pydantic import SecretStr

from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig
from cp_review.run_manifest import write_run_manifest


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


def test_write_run_manifest_includes_summary_and_artifacts(tmp_path: Path):
    settings = _settings(tmp_path)
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{\"ok\": true}", encoding="utf-8")
    manifest_path = tmp_path / "run-manifest.json"

    write_run_manifest(
        manifest_path,
        command="full-run",
        run_id="run-123",
        settings=settings,
        artifacts={"artifact_json": artifact},
        summary={"findings_count": 3, "rules_count": 10},
    )

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["command"] == "full-run"
    assert payload["run_id"] == "run-123"
    assert payload["status"] == "completed"
    assert payload["summary"]["findings_count"] == 3
    assert payload["artifacts"][0]["name"] == "artifact_json"
