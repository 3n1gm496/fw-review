"""Service layer for the local-first remediation cockpit."""

from __future__ import annotations

import json
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from cp_review.compare import compare_findings
from cp_review.doctor import run_local_readiness_checks
from cp_review.normalize.dataset import load_dataset
from cp_review.run_metrics import build_run_metrics, write_run_metrics
from cp_review.simulation import simulate_rule_change
from cp_review.validate_run import validate_run_manifest
from cp_review.web.config import WebConfig, write_web_config
from cp_review.web.db import (
    create_run_job,
    export_ticket_drafts,
    get_active_run_job,
    get_review_activity,
    import_run,
    init_db,
    latest_run_id,
    list_runs,
    query_queue,
    rebuild_db,
    record_explanation,
    record_simulation,
    update_queue_state,
    update_run_job,
)
from cp_review.web.db import (
    export_review_state as export_review_state_payload,
)

_RUN_LOCK = threading.Lock()


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _artifact_path(manifest: dict[str, Any], name: str) -> Path | None:
    for artifact in manifest.get("artifacts", []):
        if isinstance(artifact, dict) and artifact.get("name") == name:
            return Path(str(artifact["path"]))
    return None


def init_web_workspace(settings, web_config: WebConfig, *, web_config_path: Path, force: bool = False) -> dict[str, Any]:
    settings.collection.output_dir.mkdir(parents=True, exist_ok=True)
    web_config.app_dir.mkdir(parents=True, exist_ok=True)
    init_db(web_config.db_path)
    written_config = write_web_config(web_config_path, web_config, force=force)
    sync_report = sync_runs(settings, web_config)
    doctor_report = run_web_doctor(settings, web_config, web_config_path=written_config)
    return {
        "summary": "ok" if doctor_report["summary"] == "ok" else "fail",
        "web_config_path": str(written_config),
        "db_path": str(web_config.db_path),
        "app_dir": str(web_config.app_dir),
        "sync": sync_report,
        "doctor": doctor_report,
    }


def run_web_doctor(settings, web_config: WebConfig, *, web_config_path: Path) -> dict[str, Any]:
    checks = [
        {"name": "python_version", "status": "ok" if sys.version_info >= (3, 11) else "fail", "details": sys.version.split()[0]},
        {"name": "web_config", "status": "ok" if web_config_path.exists() else "fail", "details": str(web_config_path)},
        {"name": "app_dir", "status": "ok" if web_config.app_dir.exists() else "fail", "details": str(web_config.app_dir)},
        {"name": "db_path", "status": "ok" if web_config.db_path.exists() else "fail", "details": str(web_config.db_path)},
        {"name": "output_dir", "status": "ok" if settings.collection.output_dir.exists() else "fail", "details": str(settings.collection.output_dir)},
        {
            "name": "templates_dir",
            "status": "ok" if (Path(__file__).parent / "templates").exists() else "fail",
            "details": str(Path(__file__).parent / "templates"),
        },
    ]
    local_checks = run_local_readiness_checks(settings, require_credentials=False)["checks"]
    checks.extend(local_checks)
    if settings.management.ca_bundle:
        checks.append(
            {
                "name": "ca_bundle_exists",
                "status": "ok" if Path(settings.management.ca_bundle).exists() else "fail",
                "details": settings.management.ca_bundle,
            }
        )
    has_fail = any(check["status"] == "fail" for check in checks)
    return {"summary": "fail" if has_fail else "ok", "checks": checks}


def sync_runs(settings, web_config: WebConfig, *, run_id: str | None = None) -> dict[str, Any]:
    reports_root = settings.collection.output_dir / "reports"
    init_db(web_config.db_path)
    manifests = []
    if run_id:
        candidate = reports_root / run_id / "run-manifest.json"
        if candidate.exists():
            manifests.append(candidate)
    else:
        manifests = sorted(reports_root.glob("*/run-manifest.json"))
    imported: list[str] = []
    corrupted: list[str] = []
    for manifest_path in manifests:
        try:
            manifest = _load_json(manifest_path)
            queue_path = _artifact_path(manifest, "review_queue_json")
            policy_health_path = _artifact_path(manifest, "policy_health_json")
            remediation_path = _artifact_path(manifest, "top_remediation_json")
            queue_items = _load_json(queue_path) if queue_path and queue_path.exists() else None
            policy_health = _load_json(policy_health_path) if policy_health_path and policy_health_path.exists() else None
            top_remediation = _load_json(remediation_path) if remediation_path and remediation_path.exists() else None
            strict_validation = validate_run_manifest(manifest_path, strict=True)
            import_run(
                web_config.db_path,
                manifest=manifest,
                manifest_path=manifest_path,
                queue_items=queue_items,
                policy_health=policy_health,
                top_remediation=top_remediation,
                strict_validation=strict_validation,
            )
            imported.append(str(manifest.get("run_id", manifest_path.parent.name)))
        except Exception:  # noqa: BLE001
            corrupted.append(str(manifest_path))
    return {"summary": "ok" if not corrupted else "warn", "imported_runs": imported, "corrupted_manifests": corrupted}


def rebuild_run_index(settings, web_config: WebConfig) -> dict[str, Any]:
    rebuild_db(web_config.db_path)
    return sync_runs(settings, web_config)


def _reports_dir_for_run(settings, run_id: str) -> Path:
    return settings.collection.output_dir / "reports" / run_id


def _load_run_context(settings, web_config: WebConfig, run_id: str | None = None) -> tuple[str, Any, list, list, Path]:
    from cp_review.cli import _latest_dataset_path, _load_findings_for_report, _write_review_queue_bundle

    chosen_run_id = run_id or latest_run_id(web_config.db_path)
    if chosen_run_id is None:
        dataset_path = _latest_dataset_path(settings.collection.output_dir)
        dataset = load_dataset(dataset_path)
        chosen_run_id = dataset.run_id
    dataset_path = settings.collection.output_dir / "normalized" / chosen_run_id / "dataset.json"
    dataset = load_dataset(dataset_path)
    reports_dir = _reports_dir_for_run(settings, chosen_run_id)
    findings, _ = _load_findings_for_report(dataset, None, settings, reports_dir)
    queue_items, _ = _write_review_queue_bundle(dataset.run_id, findings, reports_dir)
    return chosen_run_id, dataset, findings, queue_items, reports_dir


def explain_rule(settings, web_config: WebConfig, *, rule_uid: str, run_id: str | None = None) -> dict[str, Any]:
    from cp_review.cli import _explain_rule

    selected_run_id, dataset, findings, queue_items, _ = _load_run_context(settings, web_config, run_id)
    payload = _explain_rule(dataset, findings, queue_items, rule_uid=rule_uid)
    record_explanation(web_config.db_path, run_id=selected_run_id, rule_uid=rule_uid, payload=payload)
    return payload


def simulate_rule(settings, web_config: WebConfig, *, rule_uid: str, run_id: str | None = None) -> dict[str, Any]:
    selected_run_id, dataset, findings, queue_items, _ = _load_run_context(settings, web_config, run_id)
    payload = simulate_rule_change(dataset, findings, queue_items, rule_uid=rule_uid)
    record_simulation(web_config.db_path, run_id=selected_run_id, rule_uid=rule_uid, payload=payload)
    return payload


def build_drift(settings, *, previous_run_id: str | None = None, current_run_id: str | None = None) -> dict[str, Any]:
    reports_root = settings.collection.output_dir / "reports"
    if not current_run_id or not previous_run_id:
        findings_files = sorted(reports_root.glob("*/findings.json"), key=lambda path: path.parent.name)
        if len(findings_files) < 2:
            return {
                "previous_run_id": previous_run_id,
                "current_run_id": current_run_id,
                "drift": None,
                "message": "Need at least two findings runs to build drift.",
            }
        previous_run_id = previous_run_id or findings_files[-2].parent.name
        current_run_id = current_run_id or findings_files[-1].parent.name
    previous = _load_json(reports_root / previous_run_id / "findings.json")
    current = _load_json(reports_root / current_run_id / "findings.json")
    return {
        "previous_run_id": previous_run_id,
        "current_run_id": current_run_id,
        "drift": compare_findings(previous, current),
        "message": "",
    }


def persist_review_state(
    settings,
    web_config: WebConfig,
    *,
    item_ids: list[str] | None = None,
    rule_uid: str | None = None,
    status: str | None = None,
    owner: str | None = None,
    campaign: str | None = None,
    due_date: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    updated = update_queue_state(
        web_config.db_path,
        item_ids=item_ids,
        rule_uid=rule_uid,
        status=status,
        owner=owner,
        campaign=campaign,
        due_date=due_date,
        notes=notes,
    )
    runs = {item["run_id"] for item in query_queue(web_config.db_path, limit=5000) if (item_ids and item["item_id"] in item_ids) or (rule_uid and item["rule_uid"] == rule_uid)}
    for current_run_id in runs:
        payload = export_review_state_payload(web_config.db_path, run_id=current_run_id)
        reports_dir = _reports_dir_for_run(settings, current_run_id)
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / "review-state.yaml").write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return {"summary": "ok", "updated": updated, "runs": sorted(runs)}


def export_review_state(settings, web_config: WebConfig, *, run_id: str | None, format_name: str, output_path: Path) -> Path:
    payload = export_review_state_payload(web_config.db_path, run_id=run_id)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if format_name == "json":
        output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    else:
        output_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return output_path


def export_ticket_queue(
    web_config: WebConfig,
    *,
    run_id: str | None,
    base_url: str,
    output_path: Path,
) -> Path:
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "tickets": export_ticket_drafts(web_config.db_path, base_url=base_url, run_id=run_id),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path


def build_executive_summary(web_config: WebConfig) -> dict[str, Any]:
    runs = list_runs(web_config.db_path, limit=20)
    latest = runs[0] if runs else None
    queue_items = query_queue(web_config.db_path, run_id=latest["run_id"], limit=1000) if latest else []
    overdue = [item for item in queue_items if item.get("due_date") and item.get("review_status") not in {"done", "false_positive"}]
    action_counts: dict[str, int] = {}
    for item in queue_items:
        action = str(item["action_type"])
        action_counts[action] = action_counts.get(action, 0) + 1
    trend = [
        {
            "run_id": run["run_id"],
            "generated_at": run["generated_at"],
            "queue_count": int(run["summary"].get("review_queue_count", 0)),
            "findings_count": int(run["summary"].get("findings_count", 0)),
            "health_score": ((run.get("policy_health") or {}).get("overall") or {}).get("score"),
        }
        for run in runs
    ]
    return {
        "latest_run": latest,
        "queue_action_counts": dict(sorted(action_counts.items())),
        "overdue_count": len(overdue),
        "activity": get_review_activity(web_config.db_path, run_id=latest["run_id"], limit=20) if latest else [],
        "trend": trend,
    }


def start_run_job(settings, web_config: WebConfig, *, strict_validate: bool = True) -> dict[str, Any]:
    with _RUN_LOCK:
        active = get_active_run_job(web_config.db_path)
        if active:
            return {"summary": "busy", "job": active}
        job_id = str(uuid4())
        create_run_job(web_config.db_path, job_id=job_id, message="Run queued from web UI")
        thread = threading.Thread(
            target=_run_job_worker,
            kwargs={"settings": settings, "web_config": web_config, "job_id": job_id, "strict_validate": strict_validate},
            daemon=True,
        )
        thread.start()
        return {"summary": "ok", "job_id": job_id}


def _run_job_worker(settings, web_config: WebConfig, *, job_id: str, strict_validate: bool) -> None:
    try:
        from cp_review.cli import _emit_manifest, _execute_full_run, _summary_with_queue

        update_run_job(web_config.db_path, job_id=job_id, phase="collect", message="Collecting policy snapshot")
        result = _execute_full_run(settings)
        dataset = result["dataset"]
        update_run_job(web_config.db_path, job_id=job_id, phase="validate", run_id=dataset.run_id, message="Validating generated run")
        metrics_path = write_run_metrics(
            result["run_paths"].reports_dir / "metrics.json",
            build_run_metrics(
                command="full-run",
                run_id=dataset.run_id,
                settings=settings,
                duration_seconds=round(sum(result["phase_timings"].values()), 3),
                api_call_count=result["api_call_count"],
                api_commands=result["api_commands"],
                findings_count=len(result["findings"]),
                rules_count=len(dataset.rules),
                warnings_count=len(dataset.warnings),
            ),
        )
        summary = _summary_with_queue(
            dataset,
            result["findings"],
            result["queue_items"],
            extra={"api_call_count": result["api_call_count"]},
            phase_timings=result["phase_timings"],
        )
        _emit_manifest(
            reports_dir=result["run_paths"].reports_dir,
            command="full-run",
            run_id=dataset.run_id,
            settings=settings,
            artifacts={**result["artifacts"], "metrics_json": metrics_path},
            dataset=dataset,
            findings=result["findings"],
            queue_items=result["queue_items"],
            summary={
                **summary,
                **({"policy_health_score": result["policy_health"]["overall"]["score"]} if result["policy_health"] else {}),
            },
        )
        manifest_path = result["run_paths"].reports_dir / "run-manifest.json"
        validation = validate_run_manifest(manifest_path, strict=strict_validate)
        sync_runs(settings, web_config, run_id=dataset.run_id)
        update_run_job(
            web_config.db_path,
            job_id=job_id,
            status="completed" if validation["summary"] == "ok" else "failed",
            phase="completed",
            run_id=dataset.run_id,
            message="Run completed" if validation["summary"] == "ok" else "Run completed with validation failures",
            summary=validation,
            completed=True,
        )
    except Exception as exc:  # noqa: BLE001
        update_run_job(
            web_config.db_path,
            job_id=job_id,
            status="failed",
            phase="failed",
            message=str(exc),
            completed=True,
        )
