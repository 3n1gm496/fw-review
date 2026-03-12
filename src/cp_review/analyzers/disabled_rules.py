"""Disabled-rule analyzer."""

from __future__ import annotations

from cp_review.models import FindingRecord, RuleRecord
from cp_review.scoring.priority import make_finding


def run(rules: list[RuleRecord]) -> list[FindingRecord]:
    """Flag disabled rules as cleanup candidates."""
    findings: list[FindingRecord] = []
    for rule in rules:
        if rule.enabled:
            continue
        findings.append(
            make_finding(
                rule,
                finding_type="disabled_rules",
                severity="low",
                evidence={"enabled": rule.enabled, "comments": rule.comments},
                recommended_action="REMOVE_CANDIDATE",
                review_note="Disabled rule should be validated with the policy owner and removed if no longer needed.",
            )
        )
    return findings
