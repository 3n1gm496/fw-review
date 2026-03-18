"""Risk and cleanup scoring helpers."""

from __future__ import annotations

from cp_review.models import FindingRecord, RuleRecord

SEVERITY_BASE = {"info": 5, "low": 20, "medium": 45, "high": 70, "critical": 90}
RISK_BASE = {
    "disabled_rules": 10,
    "unused_rules": 30,
    "broad_allow": 60,
    "no_log_rules": 55,
    "weak_documentation": 15,
    "exact_duplicate": 30,
    "semantic_duplicate": 35,
    "full_shadow": 40,
    "partial_shadow": 38,
    "conflicting_overlap": 70,
    "broad_rule_before_specific_rule": 65,
    "exception_rule_misordered": 75,
    "merge_candidates": 30,
    "dead_rule_after_covering_rule": 45,
    "high_risk_broad_usage": 85,
}
CLEANUP_BASE = {
    "disabled_rules": 85,
    "unused_rules": 70,
    "broad_allow": 20,
    "no_log_rules": 15,
    "weak_documentation": 25,
    "exact_duplicate": 75,
    "semantic_duplicate": 70,
    "full_shadow": 55,
    "partial_shadow": 45,
    "conflicting_overlap": 15,
    "broad_rule_before_specific_rule": 20,
    "exception_rule_misordered": 15,
    "merge_candidates": 70,
    "dead_rule_after_covering_rule": 85,
    "high_risk_broad_usage": 5,
}


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def compute_scores(rule: RuleRecord, finding_type: str, severity: str, evidence: dict | None = None) -> tuple[int, int]:
    """Compute deterministic risk and cleanup scores."""
    evidence = evidence or {}
    risk = max(SEVERITY_BASE.get(severity, 20), RISK_BASE.get(finding_type, 20))
    cleanup = CLEANUP_BASE.get(finding_type, 20)
    broad_axes = sum([rule.has_any_source, rule.has_any_destination, rule.has_any_service])
    if broad_axes:
        risk += broad_axes * 8
    if not rule.has_logging and rule.action.lower() == "accept":
        risk += 10
    if (rule.hit_count or 0) >= 100:
        risk += 12
    if (rule.hit_count or 0) == 0:
        cleanup += 10
    elif finding_type in {"disabled_rules", "unused_rules", "dead_rule_after_covering_rule"}:
        cleanup -= 15
    if not rule.enabled:
        cleanup += 10
    if not rule.has_comment:
        cleanup += 5
    if finding_type == "conflicting_overlap":
        cleanup -= 10
        if evidence.get("conflict_classification") in {"deny_then_allow_override", "same_scope_policy_conflict"}:
            risk += 10
    if finding_type == "partial_shadow" and len(evidence.get("coverage_axes", [])) >= 4:
        risk += 5
        cleanup += 5
    if finding_type == "merge_candidates" and evidence.get("merge_strategy"):
        cleanup += 5
    if broad_axes and finding_type in {"disabled_rules", "unused_rules", "dead_rule_after_covering_rule"}:
        cleanup -= 10
    return _clamp(risk), _clamp(cleanup)


def make_finding(
    rule: RuleRecord,
    finding_type: str,
    severity: str,
    evidence: dict,
    recommended_action: str,
    review_note: str,
) -> FindingRecord:
    """Build a finding with computed scores."""
    risk_score, cleanup_confidence = compute_scores(rule, finding_type, severity, evidence)
    return FindingRecord(
        finding_type=finding_type,
        severity=severity,
        risk_score=risk_score,
        cleanup_confidence=cleanup_confidence,
        package_name=rule.package_name,
        layer_name=rule.layer_name,
        rule_number=rule.rule_number,
        rule_uid=rule.rule_uid,
        rule_name=rule.rule_name,
        evidence=evidence,
        recommended_action=recommended_action,
        review_note=review_note,
    )
