from __future__ import annotations

import json
from pathlib import Path

from pydantic import SecretStr

from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig
from cp_review.run_metrics import build_run_metrics, write_run_metrics


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


def test_run_metrics_write_and_read(tmp_path: Path):
    metrics = build_run_metrics(
        command="full-run",
        run_id="run-456",
        settings=_settings(tmp_path),
        duration_seconds=3.14159,
        api_call_count=42,
        api_commands={"show-access-rulebase": 10, "show-package": 1},
        findings_count=7,
        rules_count=120,
        warnings_count=2,
    )
    output_path = tmp_path / "metrics.json"
    write_run_metrics(output_path, metrics)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["command"] == "full-run"
    assert payload["run_id"] == "run-456"
    assert payload["api_call_count"] == 42
    assert payload["findings_count"] == 7
