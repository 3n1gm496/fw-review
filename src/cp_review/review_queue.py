"""Review queue and local review-state helpers."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

from cp_review.models import FindingRecord, ReviewQueueItem, ReviewStateEntry

ACTION_MAP = {
    "disabled_rules": "REMOVE_CANDIDATE",
    "unused_rules": "REMOVE_CANDIDATE",
    "exact_duplicate": "MERGE_CANDIDATE",
    "semantic_duplicate": "MERGE_CANDIDATE",
    "merge_candidates": "MERGE_CANDIDATE",
    "full_shadow": "REORDER_CANDIDATE",
    "partial_shadow": "REORDER_CANDIDATE",
    "broad_rule_before_specific_rule": "REORDER_CANDIDATE",
    "exception_rule_misordered": "REORDER_CANDIDATE",
    "dead_rule_after_covering_rule": "REMOVE_CANDIDATE",
    "broad_allow": "RESTRICT_SCOPE",
    "high_risk_broad_usage": "RESTRICT_SCOPE",
    "no_log_rules": "RESTRICT_SCOPE",
    "conflicting_overlap": "RESTRICT_SCOPE",
}
PRIORITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
QUEUE_FIELDS = [
    "item_id",
    "run_id",
    "rule_uid",
    "package_name",
    "layer_name",
    "rule_number",
    "finding_type",
    "action_type",
    "priority",
    "confidence",
    "risk_score",
    "remove_confidence",
    "restrict_confidence",
    "reorder_confidence",
    "merge_confidence",
    "review_status",
    "owner",
    "campaign",
    "due_date",
    "why_flagged",
    "related_rules",
    "suggested_next_step",
]


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def _action_scores(finding: FindingRecord) -> tuple[int, int, int, int]:
    remove_confidence = finding.cleanup_confidence
    restrict_confidence = _clamp(finding.risk_score + (15 if finding.finding_type in {"broad_allow", "no_log_rules", "high_risk_broad_usage", "conflicting_overlap"} else 0))
    reorder_confidence = _clamp(70 + len(_related_rule_uids(finding)) * 5 if finding.finding_type in {"full_shadow", "partial_shadow", "broad_rule_before_specific_rule", "exception_rule_misordered"} else 15)
    merge_confidence = _clamp(75 + len(_related_rule_uids(finding)) * 5 if finding.finding_type in {"exact_duplicate", "semantic_duplicate", "merge_candidates"} else 10)
    return remove_confidence, restrict_confidence, reorder_confidence, merge_confidence


def _selected_confidence(action_type: str, scores: tuple[int, int, int, int]) -> int:
    remove_confidence, restrict_confidence, reorder_confidence, merge_confidence = scores
    if action_type == "REMOVE_CANDIDATE":
        return remove_confidence
    if action_type == "RESTRICT_SCOPE":
        return restrict_confidence
    if action_type == "REORDER_CANDIDATE":
        return reorder_confidence
    if action_type == "MERGE_CANDIDATE":
        return merge_confidence
    return max(scores)


def _priority(risk_score: int, confidence: int) -> str:
    weighted = max(risk_score, confidence)
    if weighted >= 85:
        return "critical"
    if weighted >= 70:
        return "high"
    if weighted >= 45:
        return "medium"
    return "low"


def _related_rule_uids(finding: FindingRecord) -> list[str]:
    raw = finding.evidence.get("related_rule_uids") or finding.evidence.get("rule_uids") or []
    if not isinstance(raw, list):
        raw = [raw]
    related = [str(item) for item in raw if str(item)]
    if finding.evidence.get("covered_by_rule_uid"):
        related.append(str(finding.evidence["covered_by_rule_uid"]))
    return sorted({item for item in related if item != finding.rule_uid})


def _why_flagged(finding: FindingRecord) -> str:
    evidence = dict(finding.evidence)
    relation = evidence.get("relation_type")
    if relation:
        residual = evidence.get("residual_differences") or {}
        residual_axes = [
            axis.replace("_only_in_rule", "")
            for axis, values in residual.items()
            if isinstance(values, list) and values
        ]
        merge_strategy = evidence.get("merge_strategy")
        conflict_classification = evidence.get("conflict_classification")
        residual_text = f" Residual differences remain on: {', '.join(residual_axes)}." if residual_axes else ""
        merge_text = f" Suggested merge pattern: {merge_strategy}." if merge_strategy else ""
        conflict_text = f" Conflict type: {conflict_classification}." if conflict_classification else ""
        return str(
            evidence.get("rationale")
            or f"{relation} detected against related rule(s) {', '.join(_related_rule_uids(finding))}."
        ) + residual_text + merge_text + conflict_text
    if finding.finding_type == "unused_rules":
        return f"Rule has zero hits in the review window (last hit: {evidence.get('hit_last_date')})."
    if finding.finding_type == "broad_allow":
        advisor_summary = evidence.get("summary")
        return (
            "Accept rule is overly broad "
            f"(axes={evidence.get('broad_axes')}, src={evidence.get('source_count')}, dst={evidence.get('destination_count')}, svc={evidence.get('service_count')})."
        ) + (f" {advisor_summary}" if advisor_summary else "")
    if finding.finding_type == "high_risk_broad_usage":
        return f"Broad allow rule has heavy observed use (hit_count={evidence.get('hit_count')})."
    if finding.finding_type == "no_log_rules":
        return f"Allow rule lacks sufficient logging (track={evidence.get('track')}, hits={evidence.get('hit_count')})."
    return finding.review_note


def _suggested_next_step(action_type: str, finding: FindingRecord) -> str:
    covered_by = finding.evidence.get("covered_by_rule_number")
    if action_type == "REMOVE_CANDIDATE":
        if covered_by:
            return f"Validate owner intent, confirm rule coverage against rule {covered_by}, disable temporarily if safe, then remove."
        return "Validate owner intent, disable temporarily if safe, monitor hits, then remove."
    if action_type == "RESTRICT_SCOPE":
        if finding.finding_type == "conflicting_overlap":
            earlier_action = finding.evidence.get("earlier_action")
            later_action = finding.evidence.get("later_action")
            return f"Validate policy intent for the {earlier_action}->{later_action} overlap, then narrow scope or reorder the exception safely."
        if finding.finding_type == "broad_allow" and finding.evidence.get("primary_restriction_axis"):
            return f"Restrict {finding.evidence['primary_restriction_axis']} first, then validate traffic and add logging if needed."
        return "Review source, destination, service and logging; narrow the rule without breaking known flows."
    if action_type == "REORDER_CANDIDATE":
        if covered_by:
            return f"Review intended exception ordering and test moving this rule above covering rule {covered_by}."
        return "Review related rules and intended exception ordering; test moving the rule above its parent/covering rule."
    if action_type == "MERGE_CANDIDATE":
        merge_strategy = finding.evidence.get("merge_strategy")
        if merge_strategy:
            return f"Compare related rules side-by-side and consolidate using {merge_strategy} if owner intent matches."
        return "Compare related rules side-by-side and consolidate into one cleaner rule if semantics are equivalent."
    return finding.review_note


def _item_id(run_id: str, finding: FindingRecord) -> str:
    return f"{run_id}:{finding.finding_type}:{finding.rule_uid}:{finding.package_name}:{finding.layer_name}:{finding.rule_number}"


def load_review_state(path: Path) -> dict[str, ReviewStateEntry]:
    if not path.exists():
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = payload.get("entries", []) if isinstance(payload, dict) else []
    result: dict[str, ReviewStateEntry] = {}
    for item in entries:
        entry = ReviewStateEntry.model_validate(item)
        result[entry.item_id] = entry
    return result


def write_review_state(path: Path, items: list[ReviewQueueItem], existing: dict[str, ReviewStateEntry] | None = None) -> Path:
    entries: list[ReviewStateEntry] = []
    now = datetime.now(UTC)
    current = existing or {}
    for item in items:
        preserved = current.get(item.item_id)
        entries.append(
            ReviewStateEntry(
                item_id=item.item_id,
                rule_uid=item.rule_uid,
                finding_type=item.finding_type,
                status=preserved.status if preserved else "new",
                owner=preserved.owner if preserved else item.owner,
                campaign=preserved.campaign if preserved else item.campaign,
                due_date=preserved.due_date if preserved else item.due_date,
                notes=preserved.notes if preserved else "",
                updated_at=preserved.updated_at if preserved else now,
            )
        )
    payload = {
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "entries": [entry.model_dump(mode="json") for entry in entries],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def build_review_queue(findings: list[FindingRecord], *, run_id: str, review_state: dict[str, ReviewStateEntry] | None = None) -> list[ReviewQueueItem]:
    items: list[ReviewQueueItem] = []
    state = review_state or {}
    for finding in findings:
        action_type = ACTION_MAP.get(finding.finding_type)
        if action_type is None:
            continue
        scores = _action_scores(finding)
        confidence = _selected_confidence(action_type, scores)
        item_id = _item_id(run_id, finding)
        preserved_state = state.get(item_id)
        items.append(
            ReviewQueueItem(
                item_id=item_id,
                run_id=run_id,
                rule_uid=finding.rule_uid,
                package_name=finding.package_name,
                layer_name=finding.layer_name,
                rule_number=finding.rule_number,
                finding_type=finding.finding_type,
                action_type=action_type,
                priority=_priority(finding.risk_score, confidence),
                confidence=confidence,
                risk_score=finding.risk_score,
                remove_confidence=scores[0],
                restrict_confidence=scores[1],
                reorder_confidence=scores[2],
                merge_confidence=scores[3],
                why_flagged=_why_flagged(finding),
                related_rules=_related_rule_uids(finding),
                suggested_next_step=_suggested_next_step(action_type, finding),
                review_status=preserved_state.status if preserved_state else "new",
                owner=preserved_state.owner if preserved_state else "",
                campaign=preserved_state.campaign if preserved_state else "",
                due_date=preserved_state.due_date if preserved_state else None,
            )
        )
    return sorted(
        items,
        key=lambda item: (
            PRIORITY_ORDER.get(item.priority, 0),
            item.confidence,
            item.risk_score,
            item.package_name,
            item.layer_name,
            item.rule_number,
        ),
        reverse=True,
    )


def review_queue_summary(items: list[ReviewQueueItem]) -> dict[str, Any]:
    return {
        "action_counts": dict(sorted(Counter(item.action_type for item in items).items())),
        "priority_counts": dict(sorted(Counter(item.priority for item in items).items())),
        "package_counts": dict(sorted(Counter(item.package_name for item in items).items())),
        "layer_counts": dict(sorted(Counter(f"{item.package_name}/{item.layer_name}" for item in items).items())),
    }


def write_review_queue_json(path: Path, items: list[ReviewQueueItem]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [item.model_dump(mode="json") for item in items]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def write_review_queue_csv(path: Path, items: list[ReviewQueueItem]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=QUEUE_FIELDS)
        writer.writeheader()
        for item in items:
            row = item.model_dump(mode="json")
            row["related_rules"] = ",".join(item.related_rules)
            writer.writerow({field: row.get(field, "") for field in QUEUE_FIELDS})
    return path


def write_review_queue_html(path: Path, items: list[ReviewQueueItem]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "reports" / "templates"),
        autoescape=select_autoescape(enabled_extensions=("html",)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("review_queue.html.j2")
    html = template.render(
        generated_at=datetime.now(UTC),
        items=items,
        summary=review_queue_summary(items),
    )
    path.write_text(html, encoding="utf-8")
    return path


def update_review_state(
    path: Path,
    *,
    item_id: str | None = None,
    rule_uid: str | None = None,
    status: str | None = None,
    owner: str | None = None,
    campaign: str | None = None,
    due_date: datetime | None = None,
    notes: str | None = None,
) -> Path:
    """Update review-state metadata for one queue item or all items matching a rule UID."""
    current = load_review_state(path)
    if not current:
        raise ValueError(f"No review-state entries found at {path}")
    matches = [
        entry
        for key, entry in current.items()
        if (item_id and key == item_id) or (rule_uid and entry.rule_uid == rule_uid)
    ]
    if not matches:
        raise ValueError("No review-state entries matched the requested selector")
    now = datetime.now(UTC)
    for entry in matches:
        if status is not None:
            entry.status = status
        if owner is not None:
            entry.owner = owner
        if campaign is not None:
            entry.campaign = campaign
        if due_date is not None:
            entry.due_date = due_date
        if notes is not None:
            entry.notes = notes
        entry.updated_at = now
    payload = {
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "entries": [entry.model_dump(mode="json") for entry in current.values()],
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path
