"""SQLite persistence for the remediation cockpit, including shared-web state."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import shutil
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cp_review.models import (
    Campaign,
    CampaignMembership,
    ReviewActivity,
    ReviewComment,
    ReviewQueueItem,
    ReviewStateEntry,
    RunJobStatus,
    TicketDraft,
    UserRole,
    WebSession,
)

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
    approval_status TEXT NOT NULL DEFAULT 'pending',
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
    activity_type TEXT NOT NULL DEFAULT 'workflow_update',
    status TEXT NOT NULL,
    approval_status TEXT NOT NULL DEFAULT 'pending',
    owner TEXT NOT NULL,
    campaign TEXT NOT NULL,
    notes TEXT NOT NULL,
    previous_state_json TEXT NOT NULL DEFAULT '{}',
    new_state_json TEXT NOT NULL DEFAULT '{}',
    changed_at TEXT NOT NULL,
    changed_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL,
    summary TEXT NOT NULL,
    due_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaign_members (
    campaign_key TEXT NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (campaign_key, username)
);
CREATE TABLE IF NOT EXISTS review_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    rule_uid TEXT NOT NULL,
    comment TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queue_run_id ON queue_items(run_id);
CREATE INDEX IF NOT EXISTS idx_queue_rule_uid ON queue_items(rule_uid);
CREATE INDEX IF NOT EXISTS idx_queue_status ON queue_items(review_status);
CREATE INDEX IF NOT EXISTS idx_runs_generated_at ON runs(generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_run_id ON review_activity(run_id);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_campaign_owner ON campaigns(owner);
"""

SCHEMA_VERSION = "4"

ROLE_ORDER = {"viewer": 1, "reviewer": 2, "approver": 3, "admin": 4}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _hash_password(password: str, *, salt: bytes | None = None) -> str:
    actual_salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=actual_salt, n=2**14, r=8, p=1)
    return f"{base64.b64encode(actual_salt).decode('ascii')}:{base64.b64encode(digest).decode('ascii')}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_b64, digest_b64 = stored_hash.split(":", 1)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(digest_b64.encode("ascii"))
    except ValueError:
        return False
    candidate = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(candidate, expected)


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path: Path) -> Path:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        _migrate_schema(conn)
        conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (SCHEMA_VERSION,),
        )
        conn.commit()
    return db_path


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def _migrate_schema(conn: sqlite3.Connection) -> None:
    _ensure_column(conn, "queue_items", "approval_status", "approval_status TEXT NOT NULL DEFAULT 'pending'")
    _ensure_column(conn, "review_activity", "activity_type", "activity_type TEXT NOT NULL DEFAULT 'workflow_update'")
    _ensure_column(conn, "review_activity", "approval_status", "approval_status TEXT NOT NULL DEFAULT 'pending'")
    _ensure_column(conn, "review_activity", "previous_state_json", "previous_state_json TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(conn, "review_activity", "new_state_json", "new_state_json TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(conn, "review_activity", "changed_by", "changed_by TEXT NOT NULL DEFAULT ''")


def rebuild_db(db_path: Path) -> Path:
    """Drop the current SQLite file and recreate it from scratch."""
    if db_path.exists():
        shutil.move(str(db_path), str(db_path.with_suffix(".bak")))
    return init_db(db_path)


def export_shared_state_snapshot(db_path: Path) -> dict[str, Any]:
    init_db(db_path)
    with connect(db_path) as conn:
        users = [dict(row) for row in conn.execute("SELECT username, role, password_hash, created_at, updated_at, disabled FROM users ORDER BY username").fetchall()]
        campaigns = [dict(row) for row in conn.execute("SELECT campaign_key, name, status, owner, summary, due_date, created_at, updated_at FROM campaigns ORDER BY campaign_key").fetchall()]
        campaign_members = [dict(row) for row in conn.execute("SELECT campaign_key, username, role FROM campaign_members ORDER BY campaign_key, username").fetchall()]
        queue_states = [
            dict(row)
            for row in conn.execute(
                "SELECT item_id, run_id, rule_uid, review_status, approval_status, owner, campaign, due_date, notes, updated_at FROM queue_items ORDER BY run_id, item_id"
            ).fetchall()
        ]
        review_comments = [dict(row) for row in conn.execute("SELECT run_id, item_id, rule_uid, comment, author, created_at FROM review_comments ORDER BY created_at").fetchall()]
        review_activity = [dict(row) for row in conn.execute("SELECT run_id, item_id, rule_uid, activity_type, status, approval_status, owner, campaign, notes, previous_state_json, new_state_json, changed_at, changed_by FROM review_activity ORDER BY changed_at").fetchall()]
    return {
        "users": users,
        "campaigns": campaigns,
        "campaign_members": campaign_members,
        "queue_states": queue_states,
        "review_comments": review_comments,
        "review_activity": review_activity,
    }


def restore_shared_state_snapshot(db_path: Path, snapshot: dict[str, Any]) -> dict[str, int]:
    init_db(db_path)
    restored = {
        "users": 0,
        "campaigns": 0,
        "campaign_members": 0,
        "queue_states": 0,
        "review_comments": 0,
        "review_activity": 0,
    }
    with connect(db_path) as conn:
        for user in snapshot.get("users", []):
            conn.execute(
                """
                INSERT OR REPLACE INTO users(username, role, password_hash, created_at, updated_at, disabled)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (
                    str(user["username"]),
                    str(user["role"]),
                    str(user["password_hash"]),
                    str(user["created_at"]),
                    str(user["updated_at"]),
                    1 if bool(user.get("disabled")) else 0,
                ),
            )
            restored["users"] += 1
        for campaign in snapshot.get("campaigns", []):
            conn.execute(
                """
                INSERT OR REPLACE INTO campaigns(campaign_key, name, status, owner, summary, due_date, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(campaign["campaign_key"]),
                    str(campaign["name"]),
                    str(campaign["status"]),
                    str(campaign["owner"]),
                    str(campaign.get("summary") or ""),
                    str(campaign["due_date"]) if campaign.get("due_date") else None,
                    str(campaign["created_at"]),
                    str(campaign["updated_at"]),
                ),
            )
            restored["campaigns"] += 1
        for member in snapshot.get("campaign_members", []):
            conn.execute(
                "INSERT OR REPLACE INTO campaign_members(campaign_key, username, role) VALUES(?, ?, ?)",
                (str(member["campaign_key"]), str(member["username"]), str(member["role"])),
            )
            restored["campaign_members"] += 1
        for state in snapshot.get("queue_states", []):
            cursor = conn.execute(
                """
                UPDATE queue_items
                SET review_status = ?, approval_status = ?, owner = ?, campaign = ?, due_date = ?, notes = ?, updated_at = ?
                WHERE item_id = ? AND run_id = ?
                """,
                (
                    str(state["review_status"]),
                    str(state.get("approval_status") or "pending"),
                    str(state.get("owner") or ""),
                    str(state.get("campaign") or ""),
                    str(state["due_date"]) if state.get("due_date") else None,
                    str(state.get("notes") or ""),
                    str(state.get("updated_at") or _now()),
                    str(state["item_id"]),
                    str(state["run_id"]),
                ),
            )
            restored["queue_states"] += int(cursor.rowcount)
        conn.execute("DELETE FROM review_comments")
        for comment in snapshot.get("review_comments", []):
            exists = conn.execute("SELECT 1 FROM queue_items WHERE item_id = ? AND run_id = ?", (str(comment["item_id"]), str(comment["run_id"]))).fetchone()
            if exists is None:
                continue
            conn.execute(
                "INSERT INTO review_comments(run_id, item_id, rule_uid, comment, author, created_at) VALUES(?, ?, ?, ?, ?, ?)",
                (
                    str(comment["run_id"]),
                    str(comment["item_id"]),
                    str(comment["rule_uid"]),
                    str(comment["comment"]),
                    str(comment["author"]),
                    str(comment["created_at"]),
                ),
            )
            restored["review_comments"] += 1
        conn.execute("DELETE FROM review_activity")
        for activity in snapshot.get("review_activity", []):
            exists = conn.execute("SELECT 1 FROM queue_items WHERE item_id = ? AND run_id = ?", (str(activity["item_id"]), str(activity["run_id"]))).fetchone()
            if exists is None:
                continue
            conn.execute(
                """
                INSERT INTO review_activity(run_id, item_id, rule_uid, activity_type, status, approval_status, owner, campaign, notes, previous_state_json, new_state_json, changed_at, changed_by)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(activity["run_id"]),
                    str(activity["item_id"]),
                    str(activity["rule_uid"]),
                    str(activity.get("activity_type") or "workflow_update"),
                    str(activity["status"]),
                    str(activity.get("approval_status") or "pending"),
                    str(activity.get("owner") or ""),
                    str(activity.get("campaign") or ""),
                    str(activity.get("notes") or ""),
                    str(activity.get("previous_state_json") or "{}"),
                    str(activity.get("new_state_json") or "{}"),
                    str(activity["changed_at"]),
                    str(activity.get("changed_by") or ""),
                ),
            )
            restored["review_activity"] += 1
        conn.commit()
    return restored


def _load_existing_state(conn: sqlite3.Connection, run_id: str) -> dict[str, dict[str, str]]:
    rows = conn.execute(
        "SELECT item_id, review_status, approval_status, owner, campaign, due_date, notes FROM queue_items WHERE run_id = ?",
        (run_id,),
    ).fetchall()
    return {
        str(row["item_id"]): {
            "review_status": str(row["review_status"]),
            "approval_status": str(row["approval_status"] or "pending"),
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
                      review_status, approval_status, owner, campaign, due_date, notes,
                      why_flagged, related_rules_json, suggested_next_step, raw_json, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        preserved.get("approval_status", queue_item.approval_status),
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


def list_review_state_entries(db_path: Path) -> list[dict[str, Any]]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT item_id, run_id, rule_uid, review_status, approval_status, owner, campaign, due_date, notes, updated_at FROM queue_items ORDER BY updated_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


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
    approval_status: str | None = None,
    owner: str | None = None,
    campaign: str | None = None,
    due_date: str | None = None,
    notes: str | None = None,
    changed_by: str = "system",
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
    with connect(db_path) as conn:
        selected_rows = conn.execute(
            f"SELECT item_id, run_id, rule_uid, review_status, approval_status, owner, campaign, due_date, notes FROM queue_items WHERE {selectors}",
            tuple(values),
        ).fetchall()
        changed_at = _now()
        changed_rows = []
        for row in selected_rows:
            previous_state = {
                "review_status": str(row["review_status"]),
                "approval_status": str(row["approval_status"] or "pending"),
                "owner": str(row["owner"] or ""),
                "campaign": str(row["campaign"] or ""),
                "due_date": str(row["due_date"] or ""),
                "notes": str(row["notes"] or ""),
            }
            new_state = {
                "review_status": status if status is not None else str(row["review_status"]),
                "approval_status": approval_status if approval_status is not None else str(row["approval_status"] or "pending"),
                "owner": owner if owner is not None else str(row["owner"] or ""),
                "campaign": campaign if campaign is not None else str(row["campaign"] or ""),
                "due_date": due_date if due_date is not None else str(row["due_date"] or ""),
                "notes": notes if notes is not None else str(row["notes"] or ""),
            }
            if new_state == previous_state:
                continue
            changed_rows.append((row, previous_state, new_state))
        for row, previous_state, new_state in changed_rows:
            conn.execute(
                """
                UPDATE queue_items
                SET review_status = ?, approval_status = ?, owner = ?, campaign = ?, due_date = ?, notes = ?, updated_at = ?
                WHERE item_id = ?
                """,
                (
                    new_state["review_status"],
                    new_state["approval_status"],
                    new_state["owner"],
                    new_state["campaign"],
                    new_state["due_date"] or None,
                    new_state["notes"],
                    changed_at,
                    str(row["item_id"]),
                ),
            )
            activity_type = "workflow_update"
            if new_state["approval_status"] != previous_state["approval_status"]:
                activity_type = "approval_update"
            elif new_state["owner"] != previous_state["owner"] or new_state["campaign"] != previous_state["campaign"]:
                activity_type = "assignment_update"
            elif new_state["notes"] != previous_state["notes"]:
                activity_type = "comment_update"
            conn.execute(
                "INSERT INTO review_activity(run_id, item_id, rule_uid, activity_type, status, approval_status, owner, campaign, notes, previous_state_json, new_state_json, changed_at, changed_by) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(row["run_id"]),
                    str(row["item_id"]),
                    str(row["rule_uid"]),
                    activity_type,
                    status if status is not None else str(row["review_status"]),
                    approval_status if approval_status is not None else str(row["approval_status"] or "pending"),
                    owner if owner is not None else str(row["owner"] or ""),
                    campaign if campaign is not None else str(row["campaign"] or ""),
                    notes if notes is not None else str(row["notes"] or ""),
                    json.dumps(previous_state, sort_keys=True),
                    json.dumps(new_state, sort_keys=True),
                    changed_at,
                    changed_by,
                ),
            )
        conn.commit()
        return len(changed_rows)


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
    return RunJobStatus(
        job_id=str(row["job_id"]),
        status=str(row["status"]),
        phase=str(row["phase"]),
        run_id=str(row["run_id"]) if row["run_id"] else None,
        message=str(row["message"] or ""),
        summary=json.loads(str(row["summary_json"] or "{}")),
        started_at=_parse_timestamp(str(row["started_at"])),
        updated_at=_parse_timestamp(str(row["updated_at"])),
        completed_at=_parse_timestamp(str(row["completed_at"])) if row["completed_at"] else None,
    ).model_dump(mode="json")


def get_recent_run_jobs(db_path: Path, *, limit: int = 10) -> list[dict[str, Any]]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM run_jobs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        result.append(
            RunJobStatus(
                job_id=str(row["job_id"]),
                status=str(row["status"]),
                phase=str(row["phase"]),
                run_id=str(row["run_id"]) if row["run_id"] else None,
                message=str(row["message"] or ""),
                summary=json.loads(str(row["summary_json"] or "{}")),
                started_at=_parse_timestamp(str(row["started_at"])),
                updated_at=_parse_timestamp(str(row["updated_at"])),
                completed_at=_parse_timestamp(str(row["completed_at"])) if row["completed_at"] else None,
            ).model_dump(mode="json")
        )
    return result


def get_review_activity(db_path: Path, *, run_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    init_db(db_path)
    where = "WHERE run_id = ?" if run_id else ""
    values: tuple[Any, ...] = (run_id, limit) if run_id else (limit,)
    with connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT run_id, item_id, rule_uid, activity_type, status, approval_status, owner, campaign, notes, changed_by, previous_state_json, new_state_json, changed_at FROM review_activity {where} ORDER BY changed_at DESC LIMIT ?",
            values,
        ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        payload = dict(row)
        payload["previous_state"] = json.loads(str(payload.pop("previous_state_json") or "{}"))
        payload["new_state"] = json.loads(str(payload.pop("new_state_json") or "{}"))
        result.append(ReviewActivity.model_validate(payload).model_dump(mode="json"))
    return result


def add_review_comment(
    db_path: Path,
    *,
    item_id: str,
    comment: str,
    author: str,
) -> dict[str, Any]:
    init_db(db_path)
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT run_id, rule_uid, review_status, approval_status, owner, campaign, due_date, notes FROM queue_items WHERE item_id = ?",
            (item_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"Unknown queue item: {item_id}")
        created_at = _now()
        duplicate = conn.execute(
            """
            SELECT run_id, item_id, rule_uid, comment, author, created_at
            FROM review_comments
            WHERE item_id = ? AND author = ? AND comment = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (item_id, author, comment),
        ).fetchone()
        if duplicate is not None:
            duplicate_created = _parse_timestamp(str(duplicate["created_at"]))
            if datetime.now(UTC) - duplicate_created <= timedelta(seconds=15):
                return ReviewComment.model_validate(dict(duplicate)).model_dump(mode="json")
        conn.execute(
            "INSERT INTO review_comments(run_id, item_id, rule_uid, comment, author, created_at) VALUES(?, ?, ?, ?, ?, ?)",
            (str(row["run_id"]), item_id, str(row["rule_uid"]), comment, author, created_at),
        )
        previous_notes = str(row["notes"] or "")
        combined_notes = previous_notes + ("\n" if previous_notes else "") + f"[{author}] {comment}"
        previous_state = {
            "review_status": str(row["review_status"]),
            "approval_status": str(row["approval_status"] or "pending"),
            "owner": str(row["owner"] or ""),
            "campaign": str(row["campaign"] or ""),
            "due_date": str(row["due_date"] or ""),
            "notes": previous_notes,
        }
        new_state = {**previous_state, "notes": combined_notes}
        conn.execute(
            "UPDATE queue_items SET notes = ?, updated_at = ? WHERE item_id = ?",
            (combined_notes, created_at, item_id),
        )
        conn.execute(
            "INSERT INTO review_activity(run_id, item_id, rule_uid, activity_type, status, approval_status, owner, campaign, notes, previous_state_json, new_state_json, changed_at, changed_by) "
            "SELECT run_id, item_id, rule_uid, ?, review_status, approval_status, owner, campaign, ?, ?, ?, ?, ? "
            "FROM queue_items WHERE item_id = ?",
            (
                "comment_added",
                combined_notes,
                json.dumps(previous_state, sort_keys=True),
                json.dumps(new_state, sort_keys=True),
                created_at,
                author,
                item_id,
            ),
        )
        conn.commit()
    return ReviewComment(
        run_id=str(row["run_id"]),
        item_id=item_id,
        rule_uid=str(row["rule_uid"]),
        comment=comment,
        author=author,
        created_at=datetime.fromisoformat(created_at),
    ).model_dump(mode="json")


def list_review_comments(db_path: Path, *, run_id: str | None = None, item_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    init_db(db_path)
    clauses: list[str] = []
    values: list[Any] = []
    if run_id:
        clauses.append("run_id = ?")
        values.append(run_id)
    if item_id:
        clauses.append("item_id = ?")
        values.append(item_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    values.append(limit)
    with connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT run_id, item_id, rule_uid, comment, author, created_at FROM review_comments {where} ORDER BY created_at DESC LIMIT ?",
            tuple(values),
        ).fetchall()
    return [ReviewComment.model_validate(dict(row)).model_dump(mode="json") for row in rows]


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
            approval_status=str(item.get("approval_status") or "pending"),
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


def upsert_user(db_path: Path, *, username: str, role: str, password: str, disabled: bool = False) -> dict[str, Any]:
    init_db(db_path)
    if role not in ROLE_ORDER:
        raise ValueError(f"Unsupported role: {role}")
    now = _now()
    password_hash = _hash_password(password)
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO users(username, role, password_hash, created_at, updated_at, disabled)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
              role=excluded.role,
              password_hash=excluded.password_hash,
              updated_at=excluded.updated_at,
              disabled=excluded.disabled
            """,
            (username, role, password_hash, now, now, 1 if disabled else 0),
        )
        conn.commit()
    return {"username": username, "role": role, "disabled": disabled}


def list_users(db_path: Path) -> list[dict[str, Any]]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT username, role, created_at, updated_at, disabled FROM users ORDER BY username"
        ).fetchall()
    return [
        {
            "username": str(row["username"]),
            "role": str(row["role"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "disabled": bool(row["disabled"]),
        }
        for row in rows
    ]


def get_user_role(db_path: Path, username: str) -> dict[str, Any] | None:
    init_db(db_path)
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT username, role, disabled FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return None
    return UserRole(username=str(row["username"]), role=str(row["role"])).model_dump(mode="json") | {
        "disabled": bool(row["disabled"])
    }


def authenticate_user(db_path: Path, *, username: str, password: str) -> dict[str, Any] | None:
    init_db(db_path)
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT username, role, password_hash, disabled FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None or bool(row["disabled"]):
        return None
    if not _verify_password(password, str(row["password_hash"])):
        return None
    return {"username": str(row["username"]), "role": str(row["role"])}


def ensure_bootstrap_admin(db_path: Path, *, username: str = "admin") -> dict[str, Any] | None:
    init_db(db_path)
    with connect(db_path) as conn:
        existing = conn.execute("SELECT username FROM users LIMIT 1").fetchone()
    if existing is not None:
        return None
    password = secrets.token_urlsafe(12)
    upsert_user(db_path, username=username, role="admin", password=password)
    return {"username": username, "temporary_password": password}


def create_session(db_path: Path, *, username: str, role: str, ttl_hours: int) -> dict[str, Any]:
    init_db(db_path)
    now = datetime.now(UTC)
    payload = WebSession(
        session_id=secrets.token_urlsafe(24),
        username=username,
        role=role,
        created_at=now,
        expires_at=now + timedelta(hours=ttl_hours),
    )
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO sessions(session_id, username, role, created_at, expires_at) VALUES(?, ?, ?, ?, ?)",
            (
                payload.session_id,
                payload.username,
                payload.role,
                payload.created_at.isoformat(),
                payload.expires_at.isoformat(),
            ),
        )
        conn.commit()
    return payload.model_dump(mode="json")


def get_session(db_path: Path, session_id: str) -> dict[str, Any] | None:
    init_db(db_path)
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT session_id, username, role, created_at, expires_at FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    if row is None:
        return None
    session = WebSession(
        session_id=str(row["session_id"]),
        username=str(row["username"]),
        role=str(row["role"]),
        created_at=_parse_timestamp(str(row["created_at"])),
        expires_at=_parse_timestamp(str(row["expires_at"])),
    )
    if session.expires_at <= datetime.now(UTC):
        delete_session(db_path, session_id)
        return None
    return session.model_dump(mode="json")


def delete_session(db_path: Path, session_id: str) -> None:
    init_db(db_path)
    with connect(db_path) as conn:
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()


def require_role(role: str, minimum_role: str) -> bool:
    return ROLE_ORDER.get(role, 0) >= ROLE_ORDER.get(minimum_role, 0)


def list_campaigns(db_path: Path) -> list[dict[str, Any]]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT campaign_key, name, status, owner, summary, due_date, created_at, updated_at FROM campaigns ORDER BY updated_at DESC, campaign_key"
        ).fetchall()
    return [
        Campaign(
            campaign_key=str(row["campaign_key"]),
            name=str(row["name"]),
            status=str(row["status"]),
            owner=str(row["owner"]),
            summary=str(row["summary"] or ""),
            due_date=_parse_timestamp(str(row["due_date"])) if row["due_date"] else None,
            created_at=_parse_timestamp(str(row["created_at"])),
            updated_at=_parse_timestamp(str(row["updated_at"])),
        ).model_dump(mode="json")
        for row in rows
    ]


def get_campaign(db_path: Path, campaign_key: str) -> dict[str, Any] | None:
    campaigns = [campaign for campaign in list_campaigns(db_path) if campaign["campaign_key"] == campaign_key]
    if not campaigns:
        return None
    return campaigns[0]


def upsert_campaign(
    db_path: Path,
    *,
    campaign_key: str,
    name: str,
    owner: str,
    summary: str = "",
    status: str = "active",
    due_date: str | None = None,
) -> dict[str, Any]:
    init_db(db_path)
    now = _now()
    with connect(db_path) as conn:
        existing = conn.execute("SELECT created_at FROM campaigns WHERE campaign_key = ?", (campaign_key,)).fetchone()
        created_at = str(existing["created_at"]) if existing else now
        conn.execute(
            """
            INSERT INTO campaigns(campaign_key, name, status, owner, summary, due_date, created_at, updated_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(campaign_key) DO UPDATE SET
              name=excluded.name,
              status=excluded.status,
              owner=excluded.owner,
              summary=excluded.summary,
              due_date=excluded.due_date,
              updated_at=excluded.updated_at
            """,
            (campaign_key, name, status, owner, summary, due_date, created_at, now),
        )
        conn.execute(
            "INSERT OR IGNORE INTO campaign_members(campaign_key, username, role) VALUES(?, ?, ?)",
            (campaign_key, owner, "owner"),
        )
        conn.commit()
    campaign = get_campaign(db_path, campaign_key)
    if campaign is None:
        raise RuntimeError(f"Campaign not persisted: {campaign_key}")
    return campaign


def add_campaign_member(db_path: Path, *, campaign_key: str, username: str, role: str = "member") -> dict[str, Any]:
    init_db(db_path)
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO campaign_members(campaign_key, username, role) VALUES(?, ?, ?)",
            (campaign_key, username, role),
        )
        conn.commit()
    return CampaignMembership(campaign_key=campaign_key, username=username, role=role).model_dump(mode="json")


def list_campaign_members(db_path: Path, campaign_key: str) -> list[dict[str, Any]]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT campaign_key, username, role FROM campaign_members WHERE campaign_key = ? ORDER BY username",
            (campaign_key,),
        ).fetchall()
    return [CampaignMembership.model_validate(dict(row)).model_dump(mode="json") for row in rows]
