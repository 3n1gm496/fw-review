"""SQLite persistence for the local-first web app."""

from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cp_review.models import ReviewActivity, ReviewQueueItem, ReviewStateEntry, TicketDraft

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    command TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    manifest_path TEXT NOT NULL,
    reports_dir TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    warnings_json TEXT NOT NULL,
    top_remediation_json TEXT,
    policy_health_json TEXT,
    validation_summary TEXT,
    strict_validation_json TEXT,
    last_synced_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run_artifacts (
    run_id TEXT NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT,
    PRIMARY KEY (run_id, name)
);
CREATE TABLE IF NOT EXISTS queue_items (
    item_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    rule_uid TEXT NOT NULL,
    package_name TEXT NOT NULL,
    layer_name TEXT NOT NULL,
    rule_number INTEGER NOT NULL,
    finding_type TEXT NOT NULL,
    action_type TEXT NOT NULL,
    priority TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    remove_confidence INTEGER NOT NULL,
    restrict_confidence INTEGER NOT NULL,
    reorder_confidence INTEGER NOT NULL,
    merge_confidence INTEGER NOT NULL,
    review_status TEXT NOT NULL,
    owner TEXT NOT NULL,
    campaign TEXT NOT NULL,
    due_date TEXT,
    notes TEXT NOT NULL,
    why_flagged TEXT NOT NULL,
    related_rules_json TEXT NOT NULL,
    suggested_next_step TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run_jobs (
    job_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    phase TEXT NOT NULL,
    run_id TEXT,
    message TEXT NOT NULL,
    summary_json TEXT,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS simulation_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    rule_uid TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS explain_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    rule_uid TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS review_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    rule_uid TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL,
    campaign TEXT NOT NULL,
    notes TEXT NOT NULL,
    changed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queue_run_id ON queue_items(run_id);
CREATE INDEX IF NOT EXISTS idx_queue_rule_uid ON queue_items(rule_uid);
CREATE INDEX IF NOT EXISTS idx_queue_status ON queue_items(review_status);
CREATE INDEX IF NOT EXISTS idx_runs_generated_at ON runs(generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_run_id ON review_activity(run_id);
"""

SCHEMA_VERSION = "2"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path: Path) -> Path:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (SCHEMA_VERSION,),
        )
        conn.commit()
    return db_path


def rebuild_db(db_path: Path) -> Path:
    """Drop the current SQLite file and recreate it from scratch."""
    if db_path.exists():
        shutil.move(str(db_path), str(db_path.with_suffix(".bak")))
    return init_db(db_path)


def _load_existing_state(conn: sqlite3.Connection, run_id: str) -> dict[str, dict[str, str]]:
    rows = conn.execute(
        "SELECT item_id, review_status, owner, campaign, due_date, notes FROM queue_items WHERE run_id = ?",
        (run_id,),
    ).fetchall()
    return {
        str(row["item_id"]): {
            "review_status": str(row["review_status"]),
            "owner": str(row["owner"]),
            "campaign": str(row["campaign"]),
            "due_date": str(row["due_date"] or ""),
            "notes": str(row["notes"] or ""),
        }
        for row in rows
    }


def import_run(
    db_path: Path,
    *,
    manifest: dict[str, Any],
    manifest_path: Path,
    queue_items: list[dict[str, Any]] | None,
    policy_health: dict[str, Any] | None,
    top_remediation: dict[str, Any] | None,
    strict_validation: dict[str, Any] | None,
) -> None:
    init_db(db_path)
    run_id = str(manifest["run_id"])
    generated_at = str(manifest.get("generated_at", _now()))
    artifacts = manifest.get("artifacts", []) if isinstance(manifest.get("artifacts"), list) else []
    warnings = manifest.get("warnings", []) if isinstance(manifest.get("warnings"), list) else []
    summary = manifest.get("summary", {}) if isinstance(manifest.get("summary"), dict) else {}
    with connect(db_path) as conn:
        existing_state = _load_existing_state(conn, run_id)
        conn.execute(
            """
            INSERT INTO runs(run_id, command, generated_at, manifest_path, reports_dir, summary_json, warnings_json,
                             top_remediation_json, policy_health_json, validation_summary, strict_validation_json, last_synced_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
              command=excluded.command,
              generated_at=excluded.generated_at,
              manifest_path=excluded.manifest_path,
              reports_dir=excluded.reports_dir,
              summary_json=excluded.summary_json,
              warnings_json=excluded.warnings_json,
              top_remediation_json=excluded.top_remediation_json,
              policy_health_json=excluded.policy_health_json,
              validation_summary=excluded.validation_summary,
              strict_validation_json=excluded.strict_validation_json,
              last_synced_at=excluded.last_synced_at
            """,
            (
                run_id,
                str(manifest.get("command", "unknown")),
                generated_at,
                str(manifest_path),
                str(manifest_path.parent),
                json.dumps(summary, sort_keys=True),
                json.dumps(warnings, sort_keys=True),
                json.dumps(top_remediation or {}, sort_keys=True),
                json.dumps(policy_health or {}, sort_keys=True),
                str((strict_validation or {}).get("summary", "unknown")),
                json.dumps(strict_validation or {}, sort_keys=True),
                _now(),
            ),
        )
        conn.execute("DELETE FROM run_artifacts WHERE run_id = ?", (run_id,))
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            conn.execute(
                "INSERT OR REPLACE INTO run_artifacts(run_id, name, path, sha256) VALUES(?, ?, ?, ?)",
                (
                    run_id,
                    str(artifact.get("name", "")),
                    str(artifact.get("path", "")),
                    str(artifact.get("sha256", "")),
                ),
            )
        if queue_items is not None:
            conn.execute("DELETE FROM queue_items WHERE run_id = ?", (run_id,))
            for item in queue_items:
                queue_item = ReviewQueueItem.model_validate(item)
                preserved = existing_state.get(queue_item.item_id, {})
                conn.execute(
                    """
                    INSERT INTO queue_items(
                      item_id, run_id, rule_uid, package_name, layer_name, rule_number,
                      finding_type, action_type, priority, confidence, risk_score,
                      remove_confidence, restrict_confidence, reorder_confidence, merge_confidence,
                      review_status, owner, campaign, due_date, notes,
                      why_flagged, related_rules_json, suggested_next_step, raw_json, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        queue_item.item_id,
                        queue_item.run_id,
                        queue_item.rule_uid,
                        queue_item.package_name,
                        queue_item.layer_name,
                        queue_item.rule_number,
                        queue_item.finding_type,
                        queue_item.action_type,
                        queue_item.priority,
                        queue_item.confidence,
                        queue_item.risk_score,
                        queue_item.remove_confidence,
                        queue_item.restrict_confidence,
                        queue_item.reorder_confidence,
                        queue_item.merge_confidence,
                        preserved.get("review_status", queue_item.review_status),
                        preserved.get("owner", queue_item.owner),
                        preserved.get("campaign", queue_item.campaign),
                        preserved.get("due_date") or (queue_item.due_date.isoformat() if queue_item.due_date else None),
                        preserved.get("notes", ""),
                        queue_item.why_flagged,
                        json.dumps(queue_item.related_rules, sort_keys=True),
                        queue_item.suggested_next_step,
                        json.dumps(queue_item.model_dump(mode="json"), sort_keys=True),
                        _now(),
                    ),
                )
        conn.commit()


def list_runs(db_path: Path, *, limit: int = 50) -> list[dict[str, Any]]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT run_id, command, generated_at, reports_dir, summary_json, warnings_json, policy_health_json, validation_summary FROM runs ORDER BY generated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        summary = json.loads(str(row["summary_json"]))
        warnings = json.loads(str(row["warnings_json"]))
        policy_health = json.loads(str(row["policy_health_json"] or "{}"))
        result.append(
            {
                "run_id": str(row["run_id"]),
                "command": str(row["command"]),
                "generated_at": str(row["generated_at"]),
                "reports_dir": str(row["reports_dir"]),
                "summary": summary,
                "warnings": warnings,
                "policy_health": policy_health,
                "validation_summary": str(row["validation_summary"] or "unknown"),
            }
        )
    return result


def get_run(db_path: Path, run_id: str) -> dict[str, Any] | None:
    init_db(db_path)
    with connect(db_path) as conn:
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        artifacts = conn.execute("SELECT name, path, sha256 FROM run_artifacts WHERE run_id = ? ORDER BY name", (run_id,)).fetchall()
    return {
        "run_id": str(row["run_id"]),
        "command": str(row["command"]),
        "generated_at": str(row["generated_at"]),
        "manifest_path": str(row["manifest_path"]),
        "reports_dir": str(row["reports_dir"]),
        "summary": json.loads(str(row["summary_json"])),
        "warnings": json.loads(str(row["warnings_json"])),
        "top_remediation": json.loads(str(row["top_remediation_json"] or "{}")),
        "policy_health": json.loads(str(row["policy_health_json"] or "{}")),
        "validation_summary": str(row["validation_summary"] or "unknown"),
        "strict_validation": json.loads(str(row["strict_validation_json"] or "{}")),
        "artifacts": [dict(artifact) for artifact in artifacts],
    }


def latest_run_id(db_path: Path) -> str | None:
    runs = list_runs(db_path, limit=1)
    return runs[0]["run_id"] if runs else None


def query_queue(
    db_path: Path,
    *,
    run_id: str | None = None,
    package: str | None = None,
    layer: str | None = None,
    action_type: str | None = None,
    priority: str | None = None,
    status: str | None = None,
    owner: str | None = None,
    campaign: str | None = None,
    sort_by: str = "priority",
    sort_dir: str = "desc",
    limit: int = 500,
) -> list[dict[str, Any]]:
    init_db(db_path)
    clauses: list[str] = []
    values: list[Any] = []
    if run_id:
        clauses.append("run_id = ?")
        values.append(run_id)
    if package:
        clauses.append("package_name = ?")
        values.append(package)
    if layer:
        clauses.append("layer_name = ?")
        values.append(layer)
    if action_type:
        clauses.append("action_type = ?")
        values.append(action_type)
    if priority:
        clauses.append("priority = ?")
        values.append(priority)
    if status:
        clauses.append("review_status = ?")
        values.append(status)
    if owner:
        clauses.append("owner = ?")
        values.append(owner)
    if campaign:
        clauses.append("campaign = ?")
        values.append(campaign)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order_map = {
        "priority": "CASE priority WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END",
        "risk": "risk_score",
        "confidence": "confidence",
        "rule_number": "rule_number",
        "package": "package_name",
        "status": "review_status",
        "updated_at": "updated_at",
    }
    order_expr = order_map.get(sort_by, order_map["priority"])
    direction = "ASC" if sort_dir == "asc" else "DESC"
    query = (
        "SELECT * FROM queue_items "
        f"{where} "
        f"ORDER BY {order_expr} {direction}, confidence DESC, risk_score DESC, package_name, layer_name, rule_number LIMIT ?"
    )
    values.append(limit)
    with connect(db_path) as conn:
        rows = conn.execute(query, tuple(values)).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["related_rules"] = json.loads(str(item.pop("related_rules_json")))
        item["raw"] = json.loads(str(item.pop("raw_json")))
        result.append(item)
    return result


def update_queue_state(
    db_path: Path,
    *,
    item_ids: list[str] | None = None,
    rule_uid: str | None = None,
    status: str | None = None,
    owner: str | None = None,
    campaign: str | None = None,
    due_date: str | None = None,
    notes: str | None = None,
) -> int:
    init_db(db_path)
    if not item_ids and not rule_uid:
        raise ValueError("item_ids or rule_uid is required")
    clauses: list[str] = []
    values: list[Any] = []
    if item_ids:
        placeholders = ",".join("?" for _ in item_ids)
        clauses.append(f"item_id IN ({placeholders})")
        values.extend(item_ids)
    if rule_uid:
        clauses.append("rule_uid = ?")
        values.append(rule_uid)
    selectors = " OR ".join(clauses)
    fields: list[str] = []
    updates: list[Any] = []
    if status is not None:
        fields.append("review_status = ?")
        updates.append(status)
    if owner is not None:
        fields.append("owner = ?")
        updates.append(owner)
    if campaign is not None:
        fields.append("campaign = ?")
        updates.append(campaign)
    if due_date is not None:
        fields.append("due_date = ?")
        updates.append(due_date)
    if notes is not None:
        fields.append("notes = ?")
        updates.append(notes)
    fields.append("updated_at = ?")
    updates.append(_now())
    with connect(db_path) as conn:
        selected_rows = conn.execute(
            f"SELECT item_id, run_id, rule_uid, review_status, owner, campaign, notes FROM queue_items WHERE {selectors}",
            tuple(values),
        ).fetchall()
        cursor = conn.execute(
            f"UPDATE queue_items SET {', '.join(fields)} WHERE {selectors}",
            tuple(updates + values),
        )
        changed_at = _now()
        for row in selected_rows:
            conn.execute(
                "INSERT INTO review_activity(run_id, item_id, rule_uid, status, owner, campaign, notes, changed_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(row["run_id"]),
                    str(row["item_id"]),
                    str(row["rule_uid"]),
                    status if status is not None else str(row["review_status"]),
                    owner if owner is not None else str(row["owner"] or ""),
                    campaign if campaign is not None else str(row["campaign"] or ""),
                    notes if notes is not None else str(row["notes"] or ""),
                    changed_at,
                ),
            )
        conn.commit()
        return int(cursor.rowcount)


def record_simulation(db_path: Path, *, run_id: str, rule_uid: str, payload: dict[str, Any]) -> None:
    init_db(db_path)
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO simulation_history(run_id, rule_uid, requested_at, payload_json) VALUES(?, ?, ?, ?)",
            (run_id, rule_uid, _now(), json.dumps(payload, sort_keys=True)),
        )
        conn.commit()


def record_explanation(db_path: Path, *, run_id: str, rule_uid: str, payload: dict[str, Any]) -> None:
    init_db(db_path)
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO explain_history(run_id, rule_uid, requested_at, payload_json) VALUES(?, ?, ?, ?)",
            (run_id, rule_uid, _now(), json.dumps(payload, sort_keys=True)),
        )
        conn.commit()


def create_run_job(db_path: Path, *, job_id: str, message: str) -> None:
    init_db(db_path)
    now = _now()
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO run_jobs(job_id, status, phase, run_id, message, summary_json, started_at, updated_at, completed_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (job_id, "running", "collect", None, message, json.dumps({}), now, now, None),
        )
        conn.commit()


def update_run_job(
    db_path: Path,
    *,
    job_id: str,
    status: str | None = None,
    phase: str | None = None,
    run_id: str | None = None,
    message: str | None = None,
    summary: dict[str, Any] | None = None,
    completed: bool = False,
) -> None:
    init_db(db_path)
    assignments: list[str] = ["updated_at = ?"]
    values: list[Any] = [_now()]
    if status is not None:
        assignments.append("status = ?")
        values.append(status)
    if phase is not None:
        assignments.append("phase = ?")
        values.append(phase)
    if run_id is not None:
        assignments.append("run_id = ?")
        values.append(run_id)
    if message is not None:
        assignments.append("message = ?")
        values.append(message)
    if summary is not None:
        assignments.append("summary_json = ?")
        values.append(json.dumps(summary, sort_keys=True))
    if completed:
        assignments.append("completed_at = ?")
        values.append(_now())
    values.append(job_id)
    with connect(db_path) as conn:
        conn.execute(f"UPDATE run_jobs SET {', '.join(assignments)} WHERE job_id = ?", tuple(values))
        conn.commit()


def get_active_run_job(db_path: Path) -> dict[str, Any] | None:
    init_db(db_path)
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM run_jobs WHERE status = 'running' ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["summary"] = json.loads(str(result.pop("summary_json") or "{}"))
    return result


def get_recent_run_jobs(db_path: Path, *, limit: int = 10) -> list[dict[str, Any]]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM run_jobs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        job = dict(row)
        job["summary"] = json.loads(str(job.pop("summary_json") or "{}"))
        result.append(job)
    return result


def get_review_activity(db_path: Path, *, run_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    init_db(db_path)
    where = "WHERE run_id = ?" if run_id else ""
    values: tuple[Any, ...] = (run_id, limit) if run_id else (limit,)
    with connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT run_id, item_id, rule_uid, status, owner, campaign, notes, changed_at "
            f"FROM review_activity {where} ORDER BY changed_at DESC LIMIT ?",
            values,
        ).fetchall()
    return [ReviewActivity.model_validate(dict(row)).model_dump(mode="json") for row in rows]


def export_review_state(db_path: Path, *, run_id: str | None = None) -> dict[str, Any]:
    init_db(db_path)
    items = query_queue(db_path, run_id=run_id, limit=5000)
    now = _now()
    entries = [
        ReviewStateEntry(
            item_id=str(item["item_id"]),
            rule_uid=str(item["rule_uid"]),
            finding_type=str(item["finding_type"]),
            status=str(item["review_status"]),
            owner=str(item["owner"]),
            campaign=str(item["campaign"]),
            due_date=datetime.fromisoformat(str(item["due_date"])) if item.get("due_date") else None,
            notes=str(item.get("notes") or ""),
            updated_at=datetime.fromisoformat(str(item["updated_at"])),
        )
        for item in items
    ]
    return {
        "schema_version": 1,
        "generated_at": now,
        "entries": [entry.model_dump(mode="json") for entry in entries],
    }


def export_ticket_drafts(
    db_path: Path,
    *,
    base_url: str,
    run_id: str | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    items = query_queue(db_path, run_id=run_id, limit=limit)
    drafts: list[dict[str, Any]] = []
    for item in items:
        draft = TicketDraft(
            item_id=str(item["item_id"]),
            run_id=str(item["run_id"]),
            title=f"[{item['action_type']}] {item['package_name']}/{item['layer_name']} rule {item['rule_number']}",
            description=f"{item['why_flagged']}\n\nSuggested next step: {item['suggested_next_step']}",
            action_type=str(item["action_type"]),
            rule_uid=str(item["rule_uid"]),
            package_name=str(item["package_name"]),
            layer_name=str(item["layer_name"]),
            priority=str(item["priority"]),
            confidence=int(item["confidence"]),
            risk_score=int(item["risk_score"]),
            owner=str(item.get("owner") or ""),
            campaign=str(item.get("campaign") or ""),
            deep_link=f"{base_url.rstrip('/')}/rules/{item['rule_uid']}?run_id={item['run_id']}",
        )
        drafts.append(draft.model_dump(mode="json"))
    return drafts
