from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cp_review.cli import app

RUNNER = CliRunner()


def _write_settings(tmp_path: Path, *, html_report: bool = True) -> Path:
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
            "  json_findings: true\n"
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
    provenance_file = tmp_path / "output" / "reports" / "smoke-analyze" / "provenance.json"
    assert provenance_file.exists()
    metrics_file = tmp_path / "output" / "reports" / "smoke-analyze" / "metrics.json"
    assert metrics_file.exists()
    metrics = json.loads(metrics_file.read_text(encoding="utf-8"))
    assert metrics["command"] == "analyze"


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
    provenance_file = tmp_path / "output" / "reports" / "smoke-report" / "provenance.json"
    assert provenance_file.exists()
    metrics_file = tmp_path / "output" / "reports" / "smoke-report" / "metrics.json"
    assert metrics_file.exists()


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
