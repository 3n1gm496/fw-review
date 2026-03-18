"""What-if simulation helpers for cleanup decisions."""

from __future__ import annotations

from typing import Any

from cp_review.analyzers.relationships import _residual_differences  # noqa: PLC2701
from cp_review.effective_scope import scope_covers, scope_overlaps
from cp_review.models import FindingRecord, NormalizedDataset, ReviewQueueItem, RuleRecord


def _rule_summary(rule: RuleRecord) -> dict[str, Any]:
    return {
        "rule_uid": rule.rule_uid,
        "rule_number": rule.rule_number,
        "rule_name": rule.rule_name,
        "package_name": rule.package_name,
        "layer_name": rule.layer_name,
        "action": rule.action,
        "enabled": rule.enabled,
    }


def simulate_rule_change(
    dataset: NormalizedDataset,
    findings: list[FindingRecord],
    queue_items: list[ReviewQueueItem],
    *,
    rule_uid: str,
) -> dict[str, Any]:
    """Estimate likely impact if one rule is removed or consolidated."""
    target = next((rule for rule in dataset.rules if rule.rule_uid == rule_uid), None)
    if target is None:
        raise ValueError(f"Rule not found: {rule_uid}")

    same_layer_rules = [
        rule
        for rule in dataset.rules
        if rule.package_name == target.package_name and rule.layer_name == target.layer_name and rule.rule_uid != rule_uid
    ]
    covering_rules: list[dict[str, Any]] = []
    overlapping_rules: list[dict[str, Any]] = []
    for rule in same_layer_rules:
        covers, axes = scope_covers(rule, target)
        overlaps = scope_overlaps(rule, target)
        if covers:
            covering_rules.append(
                {
                    **_rule_summary(rule),
                    "coverage_axes": axes,
                    "residual_differences": _residual_differences(target, rule),
                }
            )
        elif overlaps:
            overlapping_rules.append(
                {
                    **_rule_summary(rule),
                    "coverage_axes": axes,
                    "residual_differences": _residual_differences(target, rule),
                }
            )

    rule_findings = [finding.model_dump(mode="json") for finding in findings if finding.rule_uid == rule_uid]
    queue = [item.model_dump(mode="json") for item in queue_items if item.rule_uid == rule_uid]
    safe_remove_confidence = 90 if covering_rules and (target.hit_count or 0) == 0 else 55 if covering_rules else 20
    recommendation = (
        "Rule appears removable after owner validation because a covering rule exists and observed usage is low."
        if safe_remove_confidence >= 80
        else "Rule is better treated as a restrict/reorder candidate until coverage and traffic intent are validated."
    )
    return {
        "rule": target.model_dump(mode="json"),
        "queue_items": queue,
        "findings": rule_findings,
        "simulation": {
            "covering_rules": covering_rules,
            "overlapping_rules": overlapping_rules,
            "safe_remove_confidence": safe_remove_confidence,
            "recommended_path": recommendation,
        },
    }
