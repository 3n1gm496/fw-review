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
    "duplicate_candidates": 20,
    "shadow_candidates": 35,
    "high_risk_broad_usage": 85,
}
CLEANUP_BASE = {
    "disabled_rules": 85,
    "unused_rules": 70,
    "broad_allow": 20,
    "no_log_rules": 15,
    "weak_documentation": 25,
    "duplicate_candidates": 60,
    "shadow_candidates": 55,
    "high_risk_broad_usage": 5,
}


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def compute_scores(rule: RuleRecord, finding_type: str, severity: str) -> tuple[int, int]:
    """Compute deterministic risk and cleanup scores."""
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
    if not rule.enabled:
        cleanup += 10
    if not rule.has_comment:
        cleanup += 5
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
    risk_score, cleanup_confidence = compute_scores(rule, finding_type, severity)
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
