from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cp_review.cli import app

RUNNER = CliRunner()


def _write_settings(tmp_path: Path, *, html_report: bool = True, json_findings: bool = True) -> Path:
    config_path = tmp_path / "settings.yaml"
    config_path.write_text(
        (
            "management:\n"
            "  host: mgmt.example.local\n"
            "collection:\n"
            "  output_dir: ./output\n"
            "reporting:\n"
            f"  html_report: {'true' if html_report else 'false'}\n"
            "  csv_findings: true\n"
            f"  json_findings: {'true' if json_findings else 'false'}\n"
        ),
        encoding="utf-8",
    )
    return config_path


def _write_dataset(tmp_path: Path, *, run_id: str) -> Path:
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-03-12T00:00:00Z",
                "run_id": run_id,
                "source_host": "mgmt.example.local",
                "packages": ["Standard"],
                "rules": [],
                "log_evidence": {},
                "warnings": [],
                "raw_dir": "/tmp/raw",
            }
        ),
        encoding="utf-8",
    )
    return dataset_path


def _fixture_rulebase() -> dict[str, object]:
    fixture_path = Path(__file__).parent / "fixtures" / "sample_rulebase_page.json"
    return json.loads(fixture_path.read_text(encoding="utf-8"))


def _fixture_complex_rulebase() -> dict[str, object]:
    fixture_path = Path(__file__).parent / "fixtures" / "complex_rulebase_page.json"
    return json.loads(fixture_path.read_text(encoding="utf-8"))


class FakeCheckPointClient:
    def __init__(self, settings) -> None:
        self.settings = settings
        self.api_call_count = 0
        self.command_counts: dict[str, int] = {}
        self._rulebase = _fixture_rulebase()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def call_api(self, command: str, payload: dict[str, object]) -> dict[str, object]:
        self.api_call_count += 1
        self.command_counts[command] = self.command_counts.get(command, 0) + 1
        if command == "show-packages":
            return {
                "packages": [{"name": "Standard", "access-layers": [{"name": "Network", "type": "access-layer"}]}],
                "total": 1,
            }
        if command == "show-access-rulebase":
            return self._rulebase
        if command == "show-object":
            uid = str(payload["uid"])
            return {"uid": uid, "name": uid, "type": "generic-object"}
        if command == "show-logs":
            return {"logs-count": 1, "logs": [{"query": payload["query"], "action": "Accept"}]}
        raise AssertionError(f"Unexpected command: {command}")


class WarningCheckPointClient(FakeCheckPointClient):
    def __init__(self, settings) -> None:
        super().__init__(settings)
        self._rulebase = {
            "rulebase": [
                {
                    "type": "access-rule",
                    "uid": "rule-warning",
                    "rule-number": 1,
                    "name": "Broad Rule",
                    "enabled": True,
                    "action": {"name": "Accept"},
                    "source": [{"uid": "obj-missing", "name": "obj-missing"}],
                    "destination": [{"uid": "dst-any", "name": "Any", "type": "CpmiAnyObject"}],
                    "service": [{"uid": "svc-any", "name": "Any", "type": "service-any"}],
                    "track": {"name": "None"},
                    "comments": "",
                }
            ],
            "total": 1,
        }

    def call_api(self, command: str, payload: dict[str, object]) -> dict[str, object]:
        from cp_review.exceptions import CheckPointApiError

        if command == "show-object":
            raise CheckPointApiError("show-object failed")
        if command == "show-logs":
            raise CheckPointApiError("show-logs failed")
        return super().call_api(command, payload)


class MultiPackageE2ECheckPointClient(FakeCheckPointClient):
    def __init__(self, settings) -> None:
        super().__init__(settings)
        self._standard_rulebase = _fixture_rulebase()
        self._remote_rulebase = _fixture_complex_rulebase()

    def call_api(self, command: str, payload: dict[str, object]) -> dict[str, object]:
        self.api_call_count += 1
        self.command_counts[command] = self.command_counts.get(command, 0) + 1
        if command == "show-packages":
            if payload["offset"] == 0:
                return {
                    "packages": [
                        {"name": "Standard", "access-layers": [{"name": "Network", "type": "access-layer"}]},
                        {"name": "Remote", "access-layers": ["Remote-Layer"]},
                    ],
                    "total": 3,
                }
            return {
                "packages": [
                    {"name": "BrokenPackage", "access-layers": []},
                ],
                "total": 3,
            }
        if command == "show-access-rulebase":
            if payload.get("name") == "Remote-Layer":
                return self._remote_rulebase
            return self._standard_rulebase
        if command == "show-object":
            uid = str(payload["uid"])
            return {"uid": uid, "name": f"resolved-{uid}", "type": "host"}
        if command == "show-logs":
            return {"logs-count": 2, "logs": [{"query": payload["query"], "action": "Accept"}]}
        raise AssertionError(f"Unexpected command: {command}")


def test_cli_analyze_runs_without_credentials(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    config_path = _write_settings(tmp_path, html_report=False)
    dataset_path = _write_dataset(tmp_path, run_id="smoke-analyze")

    result = RUNNER.invoke(
        app,
        ["analyze", "--config", str(config_path), "--dataset-path", str(dataset_path)],
    )

    assert result.exit_code == 0
    findings_file = tmp_path / "output" / "reports" / "smoke-analyze" / "findings.json"
    assert findings_file.exists()
    manifest_file = tmp_path / "output" / "reports" / "smoke-analyze" / "run-manifest.json"
    assert manifest_file.exists()
    provenance_file = tmp_path / "output" / "reports" / "smoke-analyze" / "provenance.json"
    assert provenance_file.exists()
    metrics_file = tmp_path / "output" / "reports" / "smoke-analyze" / "metrics.json"
    assert metrics_file.exists()
    metrics = json.loads(metrics_file.read_text(encoding="utf-8"))
    assert metrics["command"] == "analyze"
    assert (tmp_path / "output" / "reports" / "smoke-analyze" / "review-queue.json").exists()
    assert (tmp_path / "output" / "reports" / "smoke-analyze" / "review-queue.html").exists()


def test_cli_report_runs_without_credentials(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    config_path = _write_settings(tmp_path, html_report=True)
    dataset_path = _write_dataset(tmp_path, run_id="smoke-report")
    findings_path = tmp_path / "findings.json"
    findings_path.write_text("[]", encoding="utf-8")

    result = RUNNER.invoke(
        app,
        [
            "report",
            "--config",
            str(config_path),
            "--dataset-path",
            str(dataset_path),
            "--findings-path",
            str(findings_path),
        ],
    )

    assert result.exit_code == 0
    report_file = tmp_path / "output" / "reports" / "smoke-report" / "report.html"
    assert report_file.exists()
    manifest_file = tmp_path / "output" / "reports" / "smoke-report" / "run-manifest.json"
    assert manifest_file.exists()
    provenance_file = tmp_path / "output" / "reports" / "smoke-report" / "provenance.json"
    assert provenance_file.exists()
    metrics_file = tmp_path / "output" / "reports" / "smoke-report" / "metrics.json"
    assert metrics_file.exists()


def test_cli_report_rebuilds_findings_when_missing(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    config_path = _write_settings(tmp_path, html_report=True)
    dataset_path = _write_dataset(tmp_path, run_id="recover-report")

    result = RUNNER.invoke(
        app,
        [
            "report",
            "--config",
            str(config_path),
            "--dataset-path",
            str(dataset_path),
        ],
    )

    assert result.exit_code == 0
    report_dir = tmp_path / "output" / "reports" / "recover-report"
    assert (report_dir / "report.html").exists()
    assert (report_dir / "findings.json").exists()
    assert (report_dir / "run-manifest.json").exists()


def test_cli_compare_generates_drift_report(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    config_path = _write_settings(tmp_path, html_report=False)
    previous_findings = tmp_path / "previous.json"
    current_findings = tmp_path / "current.json"
    previous_findings.write_text(
        json.dumps(
            [
                {
                    "finding_type": "unused_rules",
                    "rule_uid": "r1",
                    "package_name": "P",
                    "layer_name": "L",
                    "rule_number": 1,
                }
            ]
        ),
        encoding="utf-8",
    )
    current_findings.write_text(
        json.dumps(
            [
                {
                    "finding_type": "unused_rules",
                    "rule_uid": "r1",
                    "package_name": "P",
                    "layer_name": "L",
                    "rule_number": 1,
                },
                {
                    "finding_type": "no_log_rules",
                    "rule_uid": "r2",
                    "package_name": "P",
                    "layer_name": "L",
                    "rule_number": 2,
                },
            ]
        ),
        encoding="utf-8",
    )
    drift_path = tmp_path / "drift.json"

    result = RUNNER.invoke(
        app,
        [
            "compare",
            "--config",
            str(config_path),
            "--previous-findings",
            str(previous_findings),
            "--current-findings",
            str(current_findings),
            "--output-path",
            str(drift_path),
        ],
    )

    assert result.exit_code == 0
    assert drift_path.exists()
    drift = json.loads(drift_path.read_text(encoding="utf-8"))
    assert drift["new_count"] == 1
    run_reports_dir = tmp_path / "output" / "reports" / current_findings.parent.name
    assert (run_reports_dir / "drift.metrics.json").exists()
    assert (run_reports_dir / "drift.provenance.json").exists()
    assert (run_reports_dir / "drift.run-manifest.json").exists()


def test_cli_compare_generates_drift_summary_html(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    config_path = _write_settings(tmp_path, html_report=False)
    previous_findings = tmp_path / "previous.json"
    current_findings = tmp_path / "current.json"
    previous_findings.write_text("[]", encoding="utf-8")
    current_findings.write_text("[]", encoding="utf-8")

    result = RUNNER.invoke(
        app,
        [
            "compare",
            "--config",
            str(config_path),
            "--previous-findings",
            str(previous_findings),
            "--current-findings",
            str(current_findings),
            "--summary-html",
        ],
    )

    assert result.exit_code == 0
    report_dir = tmp_path / "output" / "reports" / current_findings.parent.name
    assert (report_dir / "drift-summary.html").exists()


def test_cli_collect_runs_with_fake_api(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")
    monkeypatch.setattr("cp_review.cli.CheckPointClient", FakeCheckPointClient)
    config_path = _write_settings(tmp_path, html_report=False)

    result = RUNNER.invoke(app, ["collect", "--config", str(config_path)])

    assert result.exit_code == 0
    run_dir = tmp_path / "output" / "normalized"
    datasets = list(run_dir.glob("*/dataset.json"))
    assert len(datasets) == 1
    reports_dir = tmp_path / "output" / "reports" / datasets[0].parent.name
    assert (reports_dir / "metrics.json").exists()
    assert (reports_dir / "provenance.json").exists()
    assert (reports_dir / "run-manifest.json").exists()


def test_cli_full_run_keeps_canonical_findings_when_json_disabled(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")
    monkeypatch.setattr("cp_review.cli.CheckPointClient", FakeCheckPointClient)
    config_path = _write_settings(tmp_path, html_report=False, json_findings=False)

    result = RUNNER.invoke(app, ["full-run", "--config", str(config_path)])

    assert result.exit_code == 0
    report_dirs = list((tmp_path / "output" / "reports").glob("*"))
    assert len(report_dirs) == 1
    report_dir = report_dirs[0]
    assert (report_dir / "findings.json").exists()
    assert (report_dir / "metrics.json").exists()
    assert (report_dir / "provenance.json").exists()
    assert (report_dir / "run-manifest.json").exists()


def test_cli_full_run_persists_partial_collection_warnings_in_manifest(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")
    monkeypatch.setattr("cp_review.cli.CheckPointClient", WarningCheckPointClient)
    config_path = _write_settings(tmp_path, html_report=False)

    result = RUNNER.invoke(app, ["full-run", "--config", str(config_path)])

    assert result.exit_code == 0
    report_dir = next((tmp_path / "output" / "reports").glob("*"))
    manifest = json.loads((report_dir / "run-manifest.json").read_text(encoding="utf-8"))
    codes = {item["code"] for item in manifest["warnings"]}
    assert "OBJECT_LOOKUP_FAILED" in codes
    assert "LOG_QUERY_FAILED" in codes


def test_cli_full_run_end_to_end_multi_package_fixture(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")
    monkeypatch.setattr("cp_review.cli.CheckPointClient", MultiPackageE2ECheckPointClient)
    config_path = _write_settings(tmp_path, html_report=True)

    result = RUNNER.invoke(app, ["full-run", "--config", str(config_path)])

    assert result.exit_code == 0
    report_dir = next((tmp_path / "output" / "reports").glob("*"))
    run_id = report_dir.name
    dataset = json.loads((tmp_path / "output" / "normalized" / run_id / "dataset.json").read_text(encoding="utf-8"))
    findings = json.loads((report_dir / "findings.json").read_text(encoding="utf-8"))
    manifest = json.loads((report_dir / "run-manifest.json").read_text(encoding="utf-8"))
    html_report = (report_dir / "report.html").read_text(encoding="utf-8")

    assert dataset["packages"] == ["Standard", "Remote", "BrokenPackage"]
    assert len(dataset["rules"]) == 5
    warning_codes = {item["code"] for item in dataset["warnings"]}
    assert {"INLINE_LAYER_PRESENT", "UNSUPPORTED_RULEBASE_NODE", "NO_ACCESS_LAYERS"} <= warning_codes
    finding_types = {item["finding_type"] for item in findings}
    assert {"broad_allow", "high_risk_broad_usage"} <= finding_types
    assert manifest["summary"]["rules_count"] == 5
    assert manifest["summary"]["warnings_count"] == len(dataset["warnings"])
    assert manifest["summary"]["findings_count"] == len(findings)
    assert manifest["summary"]["review_queue_count"] >= 1
    assert "BrokenPackage" in html_report
    assert "Inline-Exceptions" in html_report
    assert (report_dir / "review-queue.json").exists()
    assert (report_dir / "review-queue.html").exists()

    validate_result = RUNNER.invoke(app, ["validate-run", "--config", str(config_path), "--run-id", run_id])
    assert validate_result.exit_code == 0
    validate_payload = json.loads(validate_result.stdout)
    assert validate_payload["summary"] == "ok"


def test_cli_run_fails_strict_validation_on_structural_warnings(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")
    monkeypatch.setattr("cp_review.cli.CheckPointClient", MultiPackageE2ECheckPointClient)
    config_path = _write_settings(tmp_path, html_report=True)

    result = RUNNER.invoke(app, ["run", "--config", str(config_path)])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["summary"] == "fail"
    assert any(check["name"] == "strict_structural_warnings" and check["status"] == "fail" for check in payload["validation"]["checks"])


def test_cli_doctor_runs_local_checks(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")
    config_path = _write_settings(tmp_path, html_report=False)

    result = RUNNER.invoke(
        app,
        [
            "doctor",
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"] == "ok"


def test_cli_doctor_fails_without_credentials_by_default(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    config_path = _write_settings(tmp_path, html_report=False)

    result = RUNNER.invoke(
        app,
        [
            "doctor",
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 1


def test_cli_doctor_allows_missing_credentials_in_offline_mode(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    config_path = _write_settings(tmp_path, html_report=False)

    result = RUNNER.invoke(
        app,
        [
            "doctor",
            "--config",
            str(config_path),
            "--offline",
        ],
    )

    assert result.exit_code == 0


def test_cli_validate_run_passes_for_latest_run(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    config_path = _write_settings(tmp_path, html_report=False)
    dataset_path = _write_dataset(tmp_path, run_id="validate-ok")

    analyze_result = RUNNER.invoke(
        app,
        ["analyze", "--config", str(config_path), "--dataset-path", str(dataset_path)],
    )
    assert analyze_result.exit_code == 0

    result = RUNNER.invoke(app, ["validate-run", "--config", str(config_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"] == "ok"
    assert payload["run_id"] == "validate-ok"


def test_cli_validate_run_strict_fails_on_structural_warning(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CP_MGMT_USERNAME", "user")
    monkeypatch.setenv("CP_MGMT_PASSWORD", "pass")
    monkeypatch.setattr("cp_review.cli.CheckPointClient", MultiPackageE2ECheckPointClient)
    config_path = _write_settings(tmp_path, html_report=True)

    full_run_result = RUNNER.invoke(app, ["full-run", "--config", str(config_path)])
    assert full_run_result.exit_code == 0
    run_id = next((tmp_path / "output" / "reports").glob("*")).name

    result = RUNNER.invoke(app, ["validate-run", "--config", str(config_path), "--run-id", run_id, "--strict"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["summary"] == "fail"
    assert any(check["name"] == "strict_structural_warnings" and check["status"] == "fail" for check in payload["checks"])


def test_cli_init_materializes_operator_bootstrap_files(tmp_path: Path):
    result = RUNNER.invoke(app, ["init", "--target-dir", str(tmp_path)])

    assert result.exit_code == 0
    assert (tmp_path / "config" / "settings.yaml").exists()
    assert (tmp_path / "config" / "review_rules.yaml").exists()
    assert (tmp_path / ".env").exists()
    payload = json.loads(result.stdout)
    assert payload["summary"] == "ok"


def test_cli_queue_and_explain_surface_actionable_output(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("CP_MGMT_USERNAME", raising=False)
    monkeypatch.delenv("CP_MGMT_PASSWORD", raising=False)
    config_path = _write_settings(tmp_path, html_report=True)
    dataset_path = tmp_path / "output" / "normalized" / "queue-run" / "dataset.json"
    dataset_path.parent.mkdir(parents=True, exist_ok=True)
    dataset_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-03-12T00:00:00Z",
                "run_id": "queue-run",
                "source_host": "mgmt.example.local",
                "packages": ["Standard"],
                "rules": [
                    {
                        "package_name": "Standard",
                        "layer_name": "Network",
                        "rule_number": 10,
                        "rule_uid": "rule-10",
                        "rule_name": "Allow Any",
                        "enabled": True,
                        "action": "Accept",
                        "source": [{"name": "Any", "type": "CpmiAnyObject"}],
                        "destination": [{"name": "Any", "type": "CpmiAnyObject"}],
                        "service": [{"name": "Any", "type": "service-any"}],
                        "application_or_site": [],
                        "install_on": [],
                        "track": "None",
                        "comments": "",
                        "hit_count": 0,
                        "hit_last_date": None,
                        "has_any_source": True,
                        "has_any_destination": True,
                        "has_any_service": True,
                        "has_logging": False,
                        "has_comment": False,
                        "source_count": 1,
                        "destination_count": 1,
                        "service_count": 1,
                        "inline_layer": None,
                        "unsupported_features": [],
                        "original_rule": {},
                    }
                ],
                "log_evidence": {},
                "warnings": [],
                "raw_dir": "/tmp/raw",
            }
        ),
        encoding="utf-8",
    )
    findings_path = tmp_path / "output" / "reports" / "queue-run" / "findings.json"
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    findings_path.write_text(
        json.dumps(
            [
                {
                    "finding_type": "broad_allow",
                    "severity": "high",
                    "risk_score": 92,
                    "cleanup_confidence": 25,
                    "package_name": "Standard",
                    "layer_name": "Network",
                    "rule_number": 10,
                    "rule_uid": "rule-10",
                    "rule_name": "Allow Any",
                    "evidence": {"broad_axes": 3, "source_count": 1, "destination_count": 1, "service_count": 1},
                    "recommended_action": "RESTRICT_SOURCE_AND_ENABLE_LOGGING",
                    "review_note": "Broad allow rule should be narrowed.",
                }
            ]
        ),
        encoding="utf-8",
    )

    queue_result = RUNNER.invoke(
        app,
        ["queue", "--config", str(config_path), "--dataset-path", str(dataset_path), "--findings-path", str(findings_path)],
    )
    assert queue_result.exit_code == 0
    queue_payload = json.loads(queue_result.stdout)
    assert queue_payload["queue_items"] == 1

    explain_result = RUNNER.invoke(app, ["explain", "--config", str(config_path), "--run-id", "queue-run", "--rule-uid", "rule-10"])
    assert explain_result.exit_code == 0
    explain_payload = json.loads(explain_result.stdout)
    assert explain_payload["summary"]["finding_count"] == 1
    assert explain_payload["queue_items"][0]["action_type"] == "RESTRICT_SCOPE"
