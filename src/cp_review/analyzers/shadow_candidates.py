"""Heuristic shadow-rule analyzer."""

from __future__ import annotations

from collections import defaultdict

from cp_review.models import FindingRecord, RuleRecord
from cp_review.scoring.priority import make_finding


def _names(refs):
    return {ref.name for ref in refs}


def _covers(earlier: RuleRecord, later: RuleRecord) -> bool:
    if earlier.action.lower() != later.action.lower():
        return False
    source_ok = earlier.has_any_source or _names(earlier.source).issuperset(_names(later.source))
    dest_ok = earlier.has_any_destination or _names(earlier.destination).issuperset(_names(later.destination))
    svc_ok = earlier.has_any_service or _names(earlier.service).issuperset(_names(later.service))
    return source_ok and dest_ok and svc_ok


def run(rules: list[RuleRecord]) -> list[FindingRecord]:
    """Flag likely shadowed rules using bounded same-layer comparisons."""
    findings: list[FindingRecord] = []
    by_layer: dict[tuple[str, str], list[RuleRecord]] = defaultdict(list)
    for rule in sorted(rules, key=lambda item: (item.package_name, item.layer_name, item.rule_number)):
        key = (rule.package_name, rule.layer_name)
        prior_rules = by_layer[key][-200:]
        for earlier in prior_rules:
            if _covers(earlier, rule):
                findings.append(
                    make_finding(
                        rule,
                        finding_type="shadow_candidates",
                        severity="medium",
                        evidence={"covered_by_rule_uid": earlier.rule_uid, "covered_by_rule_number": earlier.rule_number},
                        recommended_action="MANUAL_REVIEW_REQUIRED",
                        review_note="Earlier rule appears to cover this rule across source, destination, and service. Manual review required.",
                    )
                )
                break
        by_layer[key].append(rule)
    return findings
