"""High-risk broad usage analyzer."""

from __future__ import annotations

from cp_review.config import AnalysisConfig
from cp_review.models import FindingRecord, RuleRecord
from cp_review.scoring.priority import make_finding


def run(rules: list[RuleRecord], analysis: AnalysisConfig) -> list[FindingRecord]:
    """Flag broad allow rules with heavy observed use."""
    findings: list[FindingRecord] = []
    threshold = max(100, analysis.low_hit_threshold * 20)
    for rule in rules:
        if rule.action.lower() != "accept":
            continue
        if not any([rule.has_any_source, rule.has_any_destination, rule.has_any_service]):
            continue
        if (rule.hit_count or 0) < threshold:
            continue
        findings.append(
            make_finding(
                rule,
                finding_type="high_risk_broad_usage",
                severity="critical",
                evidence={"hit_count": rule.hit_count, "has_logging": rule.has_logging},
                recommended_action="RESTRICT_SCOPE_NOT_REMOVE",
                review_note="Heavily used broad allow rule should be narrowed carefully, not treated as a cleanup removal candidate.",
            )
        )
    return findings
