from __future__ import annotations

import json
from pathlib import Path

from pydantic import SecretStr

from cp_review.collectors.packages import collect_policy_snapshot
from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig, RunPaths


class FakeClient:
    def __init__(self, fixture):
        self.fixture = fixture

    def call_api(self, command, payload):
        if command == "show-package":
            return {
                "name": "Standard",
                "access-layers": [{"name": "Network", "type": "access-layer"}],
            }
        if command == "show-access-rulebase":
            return self.fixture
        if command == "show-object":
            return {"uid": payload["uid"], "name": payload["uid"], "type": "generic-object"}
        raise AssertionError(f"Unexpected command: {command}")


def test_collect_policy_snapshot_writes_raw_and_builds_dataset(tmp_path):
    fixture_path = Path(__file__).parent / "fixtures" / "sample_rulebase_page.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    settings = AppConfig(
        management=ManagementConfig(
            host="mgmt.example.local",
            username=SecretStr("user"),
            password=SecretStr("pass"),
        ),
        collection=CollectionConfig(package="Standard", output_dir=tmp_path / "output"),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )
    run_paths = RunPaths(
        run_id="test-run",
        base_output=tmp_path / "output",
        raw_dir=tmp_path / "output" / "raw" / "test-run",
        normalized_dir=tmp_path / "output" / "normalized" / "test-run",
        reports_dir=tmp_path / "output" / "reports" / "test-run",
    )
    run_paths.raw_dir.mkdir(parents=True)
    run_paths.normalized_dir.mkdir(parents=True)
    run_paths.reports_dir.mkdir(parents=True)

    dataset = collect_policy_snapshot(FakeClient(fixture), settings, run_paths)

    assert len(dataset.rules) == 4
    assert (run_paths.raw_dir / "packages" / "Standard.json").exists()
    raw_rulebase_files = list((run_paths.raw_dir / "rulebase").glob("*.json"))
    assert raw_rulebase_files
