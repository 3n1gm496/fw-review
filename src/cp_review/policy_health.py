"""Policy health scoring and remediation summaries."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from cp_review.models import FindingRecord, NormalizedDataset, ReviewQueueItem


def build_top_remediation_actions(queue_items: list[ReviewQueueItem]) -> dict[str, Any]:
    """Build prioritized remediation shortlists for operators."""
    ordered = sorted(
        queue_items,
        key=lambda item: (item.confidence, item.risk_score, item.priority, item.package_name, item.layer_name, item.rule_number),
        reverse=True,
    )
    by_action = {
        "remove_candidates": [item.model_dump(mode="json") for item in ordered if item.action_type == "REMOVE_CANDIDATE"][:20],
        "restrict_scope": [item.model_dump(mode="json") for item in ordered if item.action_type == "RESTRICT_SCOPE"][:20],
        "reorder_candidates": [item.model_dump(mode="json") for item in ordered if item.action_type == "REORDER_CANDIDATE"][:20],
        "merge_candidates": [item.model_dump(mode="json") for item in ordered if item.action_type == "MERGE_CANDIDATE"][:20],
    }
    return {
        "summary": {key: len(value) for key, value in by_action.items()},
        "actions": by_action,
    }


def _score_bucket(rule_count: int, findings: list[FindingRecord], queue_items: list[ReviewQueueItem]) -> dict[str, Any]:
    by_type = Counter(finding.finding_type for finding in findings)
    by_action = Counter(item.action_type for item in queue_items)
    penalty = 0.0
    penalty += by_type["conflicting_overlap"] * 10
    penalty += by_type["high_risk_broad_usage"] * 8
    penalty += by_type["broad_allow"] * 5
    penalty += by_type["no_log_rules"] * 4
    penalty += by_type["partial_shadow"] * 3
    penalty += by_type["full_shadow"] * 4
    penalty += by_type["exact_duplicate"] * 2
    penalty += by_type["semantic_duplicate"] * 2
    penalty += by_type["unused_rules"] * 2
    if rule_count:
        penalty *= min(1.0, 25 / max(rule_count, 1))
    score = max(0, round(100 - penalty))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {
        "score": score,
        "grade": grade,
        "rule_count": rule_count,
        "finding_count": len(findings),
        "queue_count": len(queue_items),
        "by_finding_type": dict(sorted(by_type.items())),
        "by_action_type": dict(sorted(by_action.items())),
    }


def build_policy_health(dataset: NormalizedDataset, findings: list[FindingRecord], queue_items: list[ReviewQueueItem]) -> dict[str, Any]:
    """Build package- and layer-level health summaries."""
    overall = _score_bucket(len(dataset.rules), findings, queue_items)
    packages: dict[str, dict[str, Any]] = {}
    layers: dict[str, dict[str, Any]] = {}
    for package_name in sorted(set(rule.package_name for rule in dataset.rules)):
        package_rules = [rule for rule in dataset.rules if rule.package_name == package_name]
        package_findings = [finding for finding in findings if finding.package_name == package_name]
        package_queue = [item for item in queue_items if item.package_name == package_name]
        packages[package_name] = _score_bucket(len(package_rules), package_findings, package_queue)
    for layer_key in sorted({f"{rule.package_name}/{rule.layer_name}" for rule in dataset.rules}):
        package_name, layer_name = layer_key.split("/", maxsplit=1)
        layer_rules = [rule for rule in dataset.rules if rule.package_name == package_name and rule.layer_name == layer_name]
        layer_findings = [finding for finding in findings if finding.package_name == package_name and finding.layer_name == layer_name]
        layer_queue = [item for item in queue_items if item.package_name == package_name and item.layer_name == layer_name]
        layers[layer_key] = _score_bucket(len(layer_rules), layer_findings, layer_queue)
    return {
        "overall": overall,
        "packages": packages,
        "layers": layers,
    }


def write_json_report(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
