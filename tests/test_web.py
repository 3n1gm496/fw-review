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
from cp_review.web.db import get_review_activity, get_run, list_review_comments, query_queue

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


def _call_app(app_obj, *, method: str, path: str, body: bytes | None = None, content_type: str = "application/json", cookie: str | None = None):
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
    if cookie:
        environ["HTTP_COOKIE"] = cookie
    body_bytes = b"".join(app_obj(environ, start_response))
    headers = dict(captured.get("headers", []))
    return str(captured["status"]), headers, body_bytes.decode("utf-8")


def _bootstrap_app(tmp_path: Path):
    config_path = _write_settings(tmp_path)
    _seed_run(tmp_path)
    init_result = RUNNER.invoke(app, ["web", "init", "--config", str(config_path)])
    payload = json.loads(init_result.stdout)
    settings = load_settings(config_path, require_credentials=False)
    web_config = load_web_config(settings, config_path=tmp_path / "config" / "web.yaml")
    app_obj = WebApplication(settings, web_config, web_config_path=tmp_path / "config" / "web.yaml")
    return config_path, payload, app_obj, web_config


def _login_cookie(app_obj, *, username: str, password: str) -> str:
    status, headers, _ = _call_app(
        app_obj,
        method="POST",
        path="/login",
        body=f"username={username}&password={password}".encode(),
        content_type="application/x-www-form-urlencoded",
    )
    assert status == "302 Found"
    return str(headers["Set-Cookie"]).split(";", 1)[0]


def test_web_init_creates_config_db_and_bootstrap_admin(tmp_path: Path):
    config_path = _write_settings(tmp_path)

    result = RUNNER.invoke(app, ["web", "init", "--config", str(config_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"] == "ok"
    assert payload["bootstrap_admin"]["username"] == "admin"
    assert payload["bootstrap_admin"]["temporary_password"]
    assert (tmp_path / "config" / "web.yaml").exists()
    assert (tmp_path / "output" / "web" / "fw-review-web.db").exists()


def test_shared_login_and_routes_require_auth(tmp_path: Path):
    _, payload, app_obj, _ = _bootstrap_app(tmp_path)

    status, headers, _ = _call_app(app_obj, method="GET", path="/")
    assert status == "302 Found"
    assert headers["Location"] == "/login"

    status, headers, _ = _call_app(app_obj, method="GET", path="/", cookie="fw_review_session=expired-token")
    assert status == "302 Found"
    assert headers["Location"] == "/login?reason=session-expired"
    assert "Max-Age=0" in headers["Set-Cookie"]

    admin_cookie = _login_cookie(
        app_obj,
        username=payload["bootstrap_admin"]["username"],
        password=payload["bootstrap_admin"]["temporary_password"],
    )

    status, _, overview_html = _call_app(app_obj, method="GET", path="/", cookie=admin_cookie)
    assert status == "200 OK"
    assert "Operational Overview" in overview_html
    assert "Signed in: <strong>admin</strong>" in overview_html

    status, _, campaigns_html = _call_app(app_obj, method="GET", path="/campaigns", cookie=admin_cookie)
    assert status == "200 OK"
    assert "Campaign Board" in campaigns_html


def test_shared_rbac_campaigns_and_review_state(tmp_path: Path):
    config_path, payload, app_obj, web_config = _bootstrap_app(tmp_path)
    admin_cookie = _login_cookie(
        app_obj,
        username=payload["bootstrap_admin"]["username"],
        password=payload["bootstrap_admin"]["temporary_password"],
    )

    create_user = RUNNER.invoke(
        app,
        [
            "web",
            "create-user",
            "--config",
            str(config_path),
            "--username",
            "reviewer1",
            "--role",
            "reviewer",
            "--password",
            "secret-reviewer",
        ],
    )
    assert create_user.exit_code == 0

    create_viewer = RUNNER.invoke(
        app,
        [
            "web",
            "create-user",
            "--config",
            str(config_path),
            "--username",
            "viewer1",
            "--role",
            "viewer",
            "--password",
            "secret-viewer",
        ],
    )
    assert create_viewer.exit_code == 0

    viewer_cookie = _login_cookie(app_obj, username="viewer1", password="secret-viewer")
    reviewer_cookie = _login_cookie(app_obj, username="reviewer1", password="secret-reviewer")

    status, _, forbidden_body = _call_app(
        app_obj,
        method="POST",
        path="/api/review-state",
        body=json.dumps({"rule_uid": "rule-1", "status": "accepted"}).encode("utf-8"),
        cookie=viewer_cookie,
    )
    assert status == "403 Forbidden"
    assert "Reviewer role required" in forbidden_body

    queue_items = query_queue(web_config.db_path, run_id="run-web-001")
    status, _, approval_forbidden = _call_app(
        app_obj,
        method="POST",
        path="/api/review-state",
        body=json.dumps({"item_ids": [queue_items[0]["item_id"]], "approval_status": "approved"}).encode("utf-8"),
        cookie=viewer_cookie,
    )
    assert status == "403 Forbidden"

    status, _, reviewer_approval_forbidden = _call_app(
        app_obj,
        method="POST",
        path="/api/review-state",
        body=json.dumps({"item_ids": [queue_items[0]["item_id"]], "approval_status": "approved"}).encode("utf-8"),
        cookie=reviewer_cookie,
    )
    assert status == "403 Forbidden"
    assert "Approver role required for approval changes" in reviewer_approval_forbidden

    status, _, campaign_body = _call_app(
        app_obj,
        method="POST",
        path="/api/campaigns",
        body=json.dumps({"campaign_key": "spring-cleanup", "name": "Spring Cleanup", "summary": "Shared backlog triage"}).encode("utf-8"),
        cookie=admin_cookie,
    )
    assert status == "200 OK"
    assert json.loads(campaign_body)["campaign"]["campaign_key"] == "spring-cleanup"

    status, _, invalid_member_body = _call_app(
        app_obj,
        method="POST",
        path="/api/campaign-members",
        body=json.dumps({"campaign_key": "missing-campaign", "username": "reviewer1", "role": "lead"}).encode("utf-8"),
        cookie=admin_cookie,
    )
    assert status == "400 Bad Request"
    assert "unknown campaign" in invalid_member_body

    status, _, member_body = _call_app(
        app_obj,
        method="POST",
        path="/api/campaign-members",
        body=json.dumps({"campaign_key": "spring-cleanup", "username": "reviewer1", "role": "lead"}).encode("utf-8"),
        cookie=admin_cookie,
    )
    assert status == "200 OK"
    assert json.loads(member_body)["member"]["username"] == "reviewer1"

    status, _, update_body = _call_app(
        app_obj,
        method="POST",
        path="/api/review-state",
        body=json.dumps(
            {
                "item_ids": [queue_items[0]["item_id"]],
                "status": "accepted",
                "approval_status": "approved",
                "owner": "reviewer1",
                "campaign": "spring-cleanup",
            }
        ).encode("utf-8"),
        cookie=admin_cookie,
    )
    assert status == "200 OK"
    update_payload = json.loads(update_body)
    assert update_payload["updated"] == 1
    updated_queue = query_queue(web_config.db_path, run_id="run-web-001")
    assert updated_queue[0]["review_status"] == "accepted"
    assert updated_queue[0]["approval_status"] == "approved"
    assert updated_queue[0]["owner"] == "reviewer1"
    assert updated_queue[0]["campaign"] == "spring-cleanup"
    activity = get_review_activity(web_config.db_path, run_id="run-web-001")
    assert activity
    assert any(entry["activity_type"] == "approval_update" for entry in activity)

    status, _, comment_body = _call_app(
        app_obj,
        method="POST",
        path="/api/comments",
        body=json.dumps({"item_id": queue_items[0]["item_id"], "comment": "Owner confirmed change window"}).encode("utf-8"),
        cookie=reviewer_cookie,
    )
    assert status == "200 OK"
    assert json.loads(comment_body)["comment"]["author"] == "reviewer1"
    activity = get_review_activity(web_config.db_path, run_id="run-web-001")
    assert any(entry["activity_type"] == "comment_added" for entry in activity)

    status, _, queue_html = _call_app(app_obj, method="GET", path="/queue?run_id=run-web-001&campaign=spring-cleanup", cookie=reviewer_cookie)
    assert status == "200 OK"
    assert "spring-cleanup" in queue_html
    assert "approved" in queue_html

    status, _, campaign_html = _call_app(app_obj, method="GET", path="/campaigns", cookie=reviewer_cookie)
    assert status == "200 OK"
    assert "Spring Cleanup" in campaign_html
    assert "reviewer1" in campaign_html

    status, _, rule_html = _call_app(app_obj, method="GET", path="/rules/rule-1?run_id=run-web-001", cookie=reviewer_cookie)
    assert status == "200 OK"
    assert "Owner confirmed change window" in rule_html
    assert "Why This Rule Was Flagged" in rule_html


def test_review_state_and_comments_reject_invalid_payloads(tmp_path: Path):
    config_path, payload, app_obj, web_config = _bootstrap_app(tmp_path)
    admin_cookie = _login_cookie(
        app_obj,
        username=payload["bootstrap_admin"]["username"],
        password=payload["bootstrap_admin"]["temporary_password"],
    )
    RUNNER.invoke(
        app,
        [
            "web",
            "create-user",
            "--config",
            str(config_path),
            "--username",
            "reviewer1",
            "--role",
            "reviewer",
            "--password",
            "secret-reviewer",
        ],
    )
    reviewer_cookie = _login_cookie(app_obj, username="reviewer1", password="secret-reviewer")
    queue_item = query_queue(web_config.db_path, run_id="run-web-001")[0]

    status, _, invalid_state_body = _call_app(
        app_obj,
        method="POST",
        path="/api/review-state",
        body=json.dumps({"item_ids": [queue_item["item_id"]], "approval_status": "maybe"}).encode("utf-8"),
        cookie=admin_cookie,
    )
    assert status == "400 Bad Request"
    assert "unsupported approval status" in invalid_state_body

    status, _, invalid_comment_body = _call_app(
        app_obj,
        method="POST",
        path="/api/comments",
        body=json.dumps({"item_id": queue_item["item_id"], "comment": "   "}).encode("utf-8"),
        cookie=reviewer_cookie,
    )
    assert status == "400 Bad Request"
    assert "comment must not be empty" in invalid_comment_body


def test_web_app_artifacts_and_ticket_export(tmp_path: Path):
    _, payload, app_obj, _ = _bootstrap_app(tmp_path)
    admin_cookie = _login_cookie(
        app_obj,
        username=payload["bootstrap_admin"]["username"],
        password=payload["bootstrap_admin"]["temporary_password"],
    )

    status, _, rule_json = _call_app(app_obj, method="GET", path="/api/rules/rule-1?run_id=run-web-001", cookie=admin_cookie)
    assert status == "200 OK"
    assert json.loads(rule_json)["summary"]["finding_count"] == 1

    status, _, artifact_body = _call_app(app_obj, method="GET", path="/artifacts/run-web-001/findings_json", cookie=admin_cookie)
    assert status == "200 OK"
    assert "broad_allow" in artifact_body

    status, _, export_body = _call_app(
        app_obj,
        method="POST",
        path="/api/tickets/export",
        body=json.dumps({"run_id": "run-web-001"}).encode("utf-8"),
        cookie=admin_cookie,
    )
    assert status == "200 OK"
    export_payload = json.loads(export_body)
    assert export_payload["run_id"] == "run-web-001"
    assert (tmp_path / "output" / "reports" / "run-web-001" / "ticket-drafts.json").exists()


def test_executive_surface_includes_campaign_team_and_audit_metrics(tmp_path: Path):
    config_path, payload, app_obj, _ = _bootstrap_app(tmp_path)
    admin_cookie = _login_cookie(
        app_obj,
        username=payload["bootstrap_admin"]["username"],
        password=payload["bootstrap_admin"]["temporary_password"],
    )
    RUNNER.invoke(
        app,
        [
            "web",
            "create-user",
            "--config",
            str(config_path),
            "--username",
            "reviewer1",
            "--role",
            "reviewer",
            "--password",
            "secret-reviewer",
        ],
    )
    reviewer_cookie = _login_cookie(app_obj, username="reviewer1", password="secret-reviewer")
    status, _, campaign_body = _call_app(
        app_obj,
        method="POST",
        path="/api/campaigns",
        body=json.dumps({"campaign_key": "exec-campaign", "name": "Executive Campaign", "summary": "Track approvals"}).encode("utf-8"),
        cookie=admin_cookie,
    )
    assert status == "200 OK"
    queue_item = query_queue(load_web_config(load_settings(config_path, require_credentials=False), config_path=tmp_path / "config" / "web.yaml").db_path, run_id="run-web-001")[0]
    _call_app(
        app_obj,
        method="POST",
        path="/api/review-state",
        body=json.dumps(
            {
                "item_ids": [queue_item["item_id"]],
                "status": "accepted",
                "approval_status": "approved",
                "owner": "reviewer1",
                "campaign": "exec-campaign",
            }
        ).encode("utf-8"),
        cookie=admin_cookie,
    )
    _call_app(
        app_obj,
        method="POST",
        path="/api/comments",
        body=json.dumps({"item_id": queue_item["item_id"], "comment": "Executive-ready"}).encode("utf-8"),
        cookie=reviewer_cookie,
    )

    status, _, executive_html = _call_app(app_obj, method="GET", path="/executive", cookie=admin_cookie)
    assert status == "200 OK"
    assert "Executive Campaign" in executive_html
    assert "reviewer1" in executive_html
    assert "approved" in executive_html
    assert "comment_added" in executive_html


def test_runs_settings_and_health_pages_have_operator_friendly_summaries(tmp_path: Path):
    _, payload, app_obj, _ = _bootstrap_app(tmp_path)
    admin_cookie = _login_cookie(
        app_obj,
        username=payload["bootstrap_admin"]["username"],
        password=payload["bootstrap_admin"]["temporary_password"],
    )

    status, _, runs_html = _call_app(app_obj, method="GET", path="/runs", cookie=admin_cookie)
    assert status == "200 OK"
    assert "Run Index" in runs_html
    assert "Latest indexed run" in runs_html

    status, _, settings_html = _call_app(app_obj, method="GET", path="/settings", cookie=admin_cookie)
    assert status == "200 OK"
    assert "Shared Web Runtime" in settings_html
    assert "Provisioned users" in settings_html

    status, _, health_html = _call_app(app_obj, method="GET", path="/health", cookie=admin_cookie)
    assert status == "200 OK"
    assert "Doctor Checks" in health_html
    assert "Session TTL hours" in health_html


def test_web_serve_command_invokes_server(monkeypatch, tmp_path: Path):
    config_path = _write_settings(tmp_path)
    init_payload = json.loads(RUNNER.invoke(app, ["web", "init", "--config", str(config_path)]).stdout)
    assert init_payload["summary"] == "ok"
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
    init_result = RUNNER.invoke(app, ["web", "init", "--config", str(config_path)])
    init_payload = json.loads(init_result.stdout)

    result = RUNNER.invoke(app, ["web", "sync", "--config", str(config_path), "--rebuild"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"] == "ok"

    settings = load_settings(config_path, require_credentials=False)
    web_config = load_web_config(settings, config_path=tmp_path / "config" / "web.yaml")
    run = get_run(web_config.db_path, "run-web-001")
    assert run is not None

    app_obj = WebApplication(settings, web_config, web_config_path=tmp_path / "config" / "web.yaml")
    admin_cookie = _login_cookie(
        app_obj,
        username=init_payload["bootstrap_admin"]["username"],
        password=init_payload["bootstrap_admin"]["temporary_password"],
    )
    status, _, drift_html = _call_app(app_obj, method="GET", path="/drift", cookie=admin_cookie)
    assert status == "200 OK"
    assert "Need at least two findings runs" in drift_html


def test_web_rebuild_preserves_shared_state_and_comments(tmp_path: Path):
    config_path, payload, app_obj, web_config = _bootstrap_app(tmp_path)
    admin_cookie = _login_cookie(
        app_obj,
        username=payload["bootstrap_admin"]["username"],
        password=payload["bootstrap_admin"]["temporary_password"],
    )
    RUNNER.invoke(
        app,
        [
            "web",
            "create-user",
            "--config",
            str(config_path),
            "--username",
            "reviewer1",
            "--role",
            "reviewer",
            "--password",
            "secret-reviewer",
        ],
    )
    reviewer_cookie = _login_cookie(app_obj, username="reviewer1", password="secret-reviewer")
    queue_item = query_queue(web_config.db_path, run_id="run-web-001")[0]

    _call_app(
        app_obj,
        method="POST",
        path="/api/review-state",
        body=json.dumps(
            {
                "item_ids": [queue_item["item_id"]],
                "status": "accepted",
                "approval_status": "approved",
                "owner": "reviewer1",
                "campaign": "spring-cleanup",
                "notes": "ready for approval",
            }
        ).encode("utf-8"),
        cookie=admin_cookie,
    )
    _call_app(
        app_obj,
        method="POST",
        path="/api/comments",
        body=json.dumps({"item_id": queue_item["item_id"], "comment": "preserve this"}).encode("utf-8"),
        cookie=reviewer_cookie,
    )

    result = RUNNER.invoke(app, ["web", "sync", "--config", str(config_path), "--rebuild"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"] == "ok"
    assert payload["rebuild_guardrail"]["restored"]["queue_states"] >= 1
    assert payload["rebuild_guardrail"]["restored"]["review_comments"] >= 1

    restored_queue = query_queue(web_config.db_path, run_id="run-web-001")
    assert restored_queue[0]["review_status"] == "accepted"
    assert restored_queue[0]["approval_status"] == "approved"
    assert restored_queue[0]["owner"] == "reviewer1"
    assert restored_queue[0]["campaign"] == "spring-cleanup"

    comments = list_review_comments(web_config.db_path, run_id="run-web-001")
    assert any(comment["comment"] == "preserve this" for comment in comments)
    activity = get_review_activity(web_config.db_path, run_id="run-web-001")
    assert any(entry["activity_type"] == "comment_added" for entry in activity)
