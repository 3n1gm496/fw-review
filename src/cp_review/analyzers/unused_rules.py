"""Unused-rule analyzer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cp_review.config import AnalysisConfig
from cp_review.models import FindingRecord, RuleRecord
from cp_review.scoring.priority import make_finding


def run(rules: list[RuleRecord], analysis: AnalysisConfig) -> list[FindingRecord]:
    """Flag zero-hit rules over the configured review window."""
    findings: list[FindingRecord] = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=analysis.zero_hit_days)
    for rule in rules:
        if rule.hit_count != 0:
            continue
        if rule.hit_last_date and rule.hit_last_date > cutoff:
            continue
        severity = "medium" if any([rule.has_any_source, rule.has_any_destination, rule.has_any_service]) else "low"
        findings.append(
            make_finding(
                rule,
                finding_type="unused_rules",
                severity=severity,
                evidence={"hit_count": rule.hit_count, "hit_last_date": rule.hit_last_date},
                recommended_action="VALIDATE_WITH_OWNER_THEN_REMOVE_CANDIDATE",
                review_note="Zero-hit rule over the review window should be confirmed with the owner before removal.",
            )
        )
    return findings
