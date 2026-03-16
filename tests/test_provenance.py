from __future__ import annotations

import json
from pathlib import Path

from pydantic import SecretStr

from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig
from cp_review.provenance import build_artifact_inventory, write_provenance_file


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


def test_write_provenance_file_includes_hashed_artifacts(tmp_path: Path):
    settings = _settings(tmp_path)
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{\"ok\":true}", encoding="utf-8")
    provenance_path = tmp_path / "provenance.json"

    write_provenance_file(
        provenance_path,
        command="analyze",
        run_id="run-123",
        settings=settings,
        artifacts={"artifact_json": artifact, "missing": tmp_path / "does-not-exist.json"},
    )

    payload = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["execution"]["command"] == "analyze"
    assert payload["execution"]["run_id"] == "run-123"
    assert payload["tool"]["name"] == "cp-review"
    assert len(payload["artifacts"]) == 1
    assert payload["artifacts"][0]["name"] == "artifact_json"
    assert payload["artifacts"][0]["sha256"]


def test_build_artifact_inventory_skips_missing_files(tmp_path: Path):
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{}", encoding="utf-8")

    inventory = build_artifact_inventory(
        {
            "artifact_json": artifact,
            "missing": tmp_path / "missing.json",
        }
    )

    assert [item["name"] for item in inventory] == ["artifact_json"]
