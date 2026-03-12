"""Heuristic duplicate-rule analyzer."""

from __future__ import annotations

from collections import defaultdict

from cp_review.models import FindingRecord, RuleRecord
from cp_review.scoring.priority import make_finding


def _signature(rule: RuleRecord) -> tuple:
    return (
        rule.package_name,
        rule.layer_name,
        rule.action.lower(),
        tuple(sorted(ref.name for ref in rule.source)),
        tuple(sorted(ref.name for ref in rule.destination)),
        tuple(sorted(ref.name for ref in rule.service)),
        tuple(sorted(ref.name for ref in rule.application_or_site)),
        tuple(sorted(ref.name for ref in rule.install_on)),
        rule.enabled,
    )


def run(rules: list[RuleRecord]) -> list[FindingRecord]:
    """Flag rules with identical normalized signatures."""
    buckets: dict[tuple, list[RuleRecord]] = defaultdict(list)
    for rule in rules:
        buckets[_signature(rule)].append(rule)
    findings: list[FindingRecord] = []
    for matches in buckets.values():
        if len(matches) < 2:
            continue
        for rule in matches:
            findings.append(
                make_finding(
                    rule,
                    finding_type="duplicate_candidates",
                    severity="medium",
                    evidence={"candidate_count": len(matches), "rule_uids": [item.rule_uid for item in matches]},
                    recommended_action="CANDIDATE_DUPLICATE",
                    review_note="Normalized fields match another rule in the same layer; confirm if the rule is redundant.",
                )
            )
    return findings
