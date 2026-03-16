from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr

from cp_review.collectors.logs import collect_logs_for_rule_uids
from cp_review.config import AnalysisConfig, AppConfig, CollectionConfig, ManagementConfig, ReportingConfig, RunPaths
from cp_review.exceptions import CheckPointApiError


class FailingLogsClient:
    def call_api(self, command: str, payload: dict[str, object]) -> dict[str, object]:
        assert command == "show-logs"
        raise CheckPointApiError("log query failed")


def test_collect_logs_for_rule_uids_returns_warnings_on_partial_failures(tmp_path: Path):
    settings = AppConfig(
        management=ManagementConfig(host="mgmt.example.local", username=SecretStr("user"), password=SecretStr("pass")),
        collection=CollectionConfig(output_dir=tmp_path / "output"),
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

    evidence, warnings = collect_logs_for_rule_uids(FailingLogsClient(), settings, run_paths, ["rule-1"])

    assert evidence == {}
    assert len(warnings) == 1
    assert warnings[0].code == "LOG_QUERY_FAILED"
    assert warnings[0].rule_uid == "rule-1"
