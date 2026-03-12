"""No-log analyzer for risky allow rules."""

from __future__ import annotations

from cp_review.config import AnalysisConfig
from cp_review.models import FindingRecord, RuleRecord
from cp_review.scoring.priority import make_finding


def run(rules: list[RuleRecord], analysis: AnalysisConfig) -> list[FindingRecord]:
    """Flag risky allow rules without sufficient logging."""
    findings: list[FindingRecord] = []
    for rule in rules:
        if rule.action.lower() != "accept" or rule.has_logging:
            continue
        risky = any([rule.has_any_source, rule.has_any_destination, rule.has_any_service]) or (rule.hit_count or 0) > analysis.low_hit_threshold
        if not risky:
            continue
        findings.append(
            make_finding(
                rule,
                finding_type="no_log_rules",
                severity="high" if (rule.hit_count or 0) > analysis.low_hit_threshold else "medium",
                evidence={"track": rule.track, "hit_count": rule.hit_count},
                recommended_action="ENABLE_LOGGING",
                review_note="Routinely used or broad allow rules should produce local evidence for operational review.",
            )
        )
    return findings
