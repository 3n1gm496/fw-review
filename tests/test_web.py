from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

from pydantic import SecretStr
from typer.testing import CliRunner

from cp_review.cli import app
from cp_review.config import (
    AnalysisConfig,
    AppConfig,
    CollectionConfig,
    ManagementConfig,
    ReportingConfig,
    load_settings,
)
from cp_review.models import FindingRecord
from cp_review.normalize.dataset import load_dataset
from cp_review.policy_health import build_policy_health, build_top_remediation_actions
from cp_review.review_queue import (
    build_review_queue,
    write_review_queue_csv,
    write_review_queue_html,
    write_review_queue_json,
    write_review_state,
)
from cp_review.run_manifest import write_run_manifest
from cp_review.web.app import WebApplication
from cp_review.web.config import load_web_config
from cp_review.web.db import get_review_activity, get_run, query_queue

RUNNER = CliRunner()


def _write_settings(tmp_path: Path) -> Path:
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "settings.yaml"
    config_path.write_text(
        (
            "management:\n"
            "  host: mgmt.example.local\n"
            "collection:\n"
            "  output_dir: ./output\n"
            "reporting:\n"
            "  html_report: true\n"
            "  csv_findings: true\n"
            "  json_findings: true\n"
        ),
        encoding="utf-8",
    )
    return config_path


def _app_settings(tmp_path: Path) -> AppConfig:
    return AppConfig(
        management=ManagementConfig(host="mgmt.example.local", username=SecretStr("user"), password=SecretStr("pass")),
        collection=CollectionConfig(output_dir=tmp_path / "output"),
        analysis=AnalysisConfig(),
        reporting=ReportingConfig(),
    )


def _seed_run(tmp_path: Path, *, run_id: str = "run-web-001") -> Path:
    settings = _app_settings(tmp_path)
    normalized_dir = settings.collection.output_dir / "normalized" / run_id
    reports_dir = settings.collection.output_dir / "reports" / run_id
    normalized_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    dataset_payload = {
        "generated_at": "2026-03-18T10:00:00Z",
        "run_id": run_id,
        "source_host": "mgmt.example.local",
        "packages": ["Standard"],
        "rules": [
            {
                "package_name": "Standard",
                "layer_name": "Network",
                "rule_number": 10,
                "rule_uid": "rule-1",
                "rule_name": "Allow Any to App",
                "enabled": True,
                "action": "Accept",
                "source": [{"name": "Any", "type": "CpmiAnyObject"}],
                "destination": [{"name": "App-Servers", "type": "group", "effective_members": ["app-1"]}],
                "service": [{"name": "Any", "type": "service-any"}],
                "application_or_site": [],
                "install_on": [{"name": "ClusterA", "type": "simple-gateway"}],
                "track": "None",
                "comments": "",
                "hit_count": 0,
                "hit_last_date": None,
                "has_any_source": True,
                "has_any_destination": False,
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
        "raw_dir": str(tmp_path / "output" / "raw" / run_id),
    }
    dataset_path = normalized_dir / "dataset.json"
    dataset_path.write_text(json.dumps(dataset_payload), encoding="utf-8")
    dataset = load_dataset(dataset_path)
    findings = [
        FindingRecord(
            finding_type="broad_allow",
            severity="high",
            risk_score=82,
            cleanup_confidence=40,
            package_name="Standard",
            layer_name="Network",
            rule_number=10,
            rule_uid="rule-1",
            rule_name="Allow Any to App",
            evidence={
                "broad_axes": ["source", "service"],
                "source_count": 1,
                "destination_count": 1,
                "service_count": 1,
                "summary": "Start by narrowing source scope.",
                "primary_restriction_axis": "source",
            },
            recommended_action="Restrict the rule.",
            review_note="Rule is too broad.",
        )
    ]
    findings_path = reports_dir / "findings.json"
    findings_path.write_text(json.dumps([finding.model_dump(mode="json") for finding in findings], indent=2), encoding="utf-8")
    queue_items = build_review_queue(findings, run_id=run_id)
    write_review_queue_json(reports_dir / "review-queue.json", queue_items)
    write_review_queue_csv(reports_dir / "review-queue.csv", queue_items)
    write_review_queue_html(reports_dir / "review-queue.html", queue_items)
    write_review_state(reports_dir / "review-state.yaml", queue_items)
    top_remediation = build_top_remediation_actions(queue_items)
    policy_health = build_policy_health(dataset, findings, queue_items)
    (reports_dir / "top-remediation.json").write_text(json.dumps(top_remediation, indent=2), encoding="utf-8")
    (reports_dir / "policy-health.json").write_text(json.dumps(policy_health, indent=2), encoding="utf-8")
    (reports_dir / "report.html").write_text("<html><body>report</body></html>", encoding="utf-8")
    (reports_dir / "metrics.json").write_text(json.dumps({"command": "full-run", "run_id": run_id}), encoding="utf-8")
    (reports_dir / "provenance.json").write_text("{}", encoding="utf-8")
    write_run_manifest(
        reports_dir / "run-manifest.json",
        command="full-run",
        run_id=run_id,
        settings=settings,
        artifacts={
            "dataset_json": dataset_path,
            "findings_json": findings_path,
            "report_html": reports_dir / "report.html",
            "metrics_json": reports_dir / "metrics.json",
            "provenance_json": reports_dir / "provenance.json",
            "review_queue_json": reports_dir / "review-queue.json",
            "review_queue_csv": reports_dir / "review-queue.csv",
            "review_queue_html": reports_dir / "review-queue.html",
            "review_state_yaml": reports_dir / "review-state.yaml",
            "top_remediation_json": reports_dir / "top-remediation.json",
            "policy_health_json": reports_dir / "policy-health.json",
        },
        summary={
            "findings_count": 1,
            "review_queue_count": len(queue_items),
            "rules_count": 1,
            "warnings_count": 0,
            "action_counts": {"RESTRICT_SCOPE": 1},
        },
    )
    return reports_dir / "run-manifest.json"


def _call_app(app_obj, *, method: str, path: str, body: bytes | None = None, content_type: str = "application/json"):
    captured: dict[str, object] = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path.split("?", 1)[0],
        "QUERY_STRING": path.split("?", 1)[1] if "?" in path else "",
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(body or b"")),
        "wsgi.input": BytesIO(body or b""),
    }
    body_bytes = b"".join(app_obj(environ, start_response))
    return str(captured["status"]), body_bytes.decode("utf-8")


def test_web_init_creates_config_and_db(tmp_path: Path):
    config_path = _write_settings(tmp_path)

    result = RUNNER.invoke(app, ["web", "init", "--config", str(config_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"] == "ok"
    assert (tmp_path / "config" / "web.yaml").exists()
    assert (tmp_path / "output" / "web" / "fw-review-web.db").exists()


def test_web_sync_imports_run_into_sqlite(tmp_path: Path):
    config_path = _write_settings(tmp_path)
    _seed_run(tmp_path)
    RUNNER.invoke(app, ["web", "init", "--config", str(config_path)])

    result = RUNNER.invoke(app, ["web", "sync", "--config", str(config_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"] == "ok"
    settings = load_settings(config_path, require_credentials=False)
    web_config = load_web_config(settings, config_path=tmp_path / "config" / "web.yaml")
    run = get_run(web_config.db_path, "run-web-001")
    assert run is not None
    assert run["summary"]["findings_count"] == 1
    assert query_queue(web_config.db_path, run_id="run-web-001")


def test_web_app_routes_and_review_state_api(tmp_path: Path):
    config_path = _write_settings(tmp_path)
    _seed_run(tmp_path)
    RUNNER.invoke(app, ["web", "init", "--config", str(config_path)])
    settings = load_settings(config_path, require_credentials=False)
    web_config = load_web_config(settings, config_path=tmp_path / "config" / "web.yaml")
    app_obj = WebApplication(settings, web_config, web_config_path=tmp_path / "config" / "web.yaml")

    status, overview_html = _call_app(app_obj, method="GET", path="/")
    assert status == "200 OK"
    assert "Operational Overview" in overview_html

    status, queue_html = _call_app(app_obj, method="GET", path="/queue?run_id=run-web-001")
    assert status == "200 OK"
    assert "Remediation Queue" in queue_html
    assert "Apply To Selected" in queue_html

    status, executive_html = _call_app(app_obj, method="GET", path="/executive")
    assert status == "200 OK"
    assert "Executive Surface" in executive_html

    status, rule_json = _call_app(app_obj, method="GET", path="/api/rules/rule-1?run_id=run-web-001")
    assert status == "200 OK"
    payload = json.loads(rule_json)
    assert payload["rule"]["rule_uid"] == "rule-1"
    assert payload["summary"]["finding_count"] == 1

    queue_items = query_queue(web_config.db_path, run_id="run-web-001")
    status, update_body = _call_app(
        app_obj,
        method="POST",
        path="/api/review-state",
        body=json.dumps({"item_ids": [queue_items[0]["item_id"]], "status": "accepted", "owner": "secops"}).encode("utf-8"),
    )
    assert status == "200 OK"
    update_payload = json.loads(update_body)
    assert update_payload["updated"] == 1
    updated_queue = query_queue(web_config.db_path, run_id="run-web-001")
    assert updated_queue[0]["review_status"] == "accepted"
    assert updated_queue[0]["owner"] == "secops"
    assert get_review_activity(web_config.db_path, run_id="run-web-001")

    status, artifact_body = _call_app(app_obj, method="GET", path="/artifacts/run-web-001/findings_json")
    assert status == "200 OK"
    assert "broad_allow" in artifact_body

    status, export_body = _call_app(app_obj, method="POST", path="/api/tickets/export", body=json.dumps({"run_id": "run-web-001"}).encode("utf-8"))
    assert status == "200 OK"
    export_payload = json.loads(export_body)
    assert export_payload["run_id"] == "run-web-001"
    assert (tmp_path / "output" / "reports" / "run-web-001" / "ticket-drafts.json").exists()


def test_web_serve_command_invokes_server(monkeypatch, tmp_path: Path):
    config_path = _write_settings(tmp_path)
    RUNNER.invoke(app, ["web", "init", "--config", str(config_path)])
    called: dict[str, object] = {}

    def _fake_serve(settings, web_config, *, web_config_path):
        called["host"] = web_config.host
        called["port"] = web_config.port
        called["path"] = str(web_config_path)

    monkeypatch.setattr("cp_review.cli.serve_web_app", _fake_serve)

    result = RUNNER.invoke(app, ["web", "serve", "--config", str(config_path), "--host", "127.0.0.1", "--port", "8877"])

    assert result.exit_code == 0
    assert called["host"] == "127.0.0.1"
    assert called["port"] == 8877
    assert str(called["path"]).endswith("config/web.yaml")


def test_web_sync_rebuild_and_drift_fallback(tmp_path: Path):
    config_path = _write_settings(tmp_path)
    _seed_run(tmp_path)
    RUNNER.invoke(app, ["web", "init", "--config", str(config_path)])

    result = RUNNER.invoke(app, ["web", "sync", "--config", str(config_path), "--rebuild"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"] == "ok"

    settings = load_settings(config_path, require_credentials=False)
    web_config = load_web_config(settings, config_path=tmp_path / "config" / "web.yaml")
    app_obj = WebApplication(settings, web_config, web_config_path=tmp_path / "config" / "web.yaml")
    status, drift_html = _call_app(app_obj, method="GET", path="/drift")
    assert status == "200 OK"
    assert "Need at least two findings runs" in drift_html
