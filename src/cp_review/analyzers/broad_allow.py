"""Broad allow-rule analyzer."""

from __future__ import annotations

from cp_review.broad_advisor import advise_broad_rule
from cp_review.config import AnalysisConfig
from cp_review.models import FindingRecord, RuleRecord
from cp_review.scoring.priority import make_finding


def _is_broad(rule: RuleRecord, threshold: int) -> tuple[bool, dict]:
    broad_axes = sum([rule.has_any_source, rule.has_any_destination, rule.has_any_service])
    large_sets = rule.source_count >= threshold or rule.destination_count >= threshold or rule.service_count >= threshold
    broad = broad_axes > 1 or rule.has_any_service or large_sets or (rule.has_any_source and rule.has_any_destination)
    return broad, {
        "broad_axes": broad_axes,
        "large_sets": large_sets,
        "source_count": rule.source_count,
        "destination_count": rule.destination_count,
        "service_count": rule.service_count,
    }


def run(rules: list[RuleRecord], analysis: AnalysisConfig) -> list[FindingRecord]:
    """Flag overly permissive Accept rules."""
    findings: list[FindingRecord] = []
    for rule in rules:
        if rule.action.lower() != "accept":
            continue
        broad, evidence = _is_broad(rule, analysis.broad_group_size_threshold)
        if not broad:
            continue
        severity = "high" if not rule.has_logging or evidence["broad_axes"] > 1 else "medium"
        recommendation = "RESTRICT_SOURCE"
        if rule.has_any_destination:
            recommendation = "RESTRICT_DESTINATION"
        if rule.has_any_service:
            recommendation = "RESTRICT_SERVICE"
        if not rule.has_logging:
            recommendation = f"{recommendation}_AND_ENABLE_LOGGING"
        finding = make_finding(
            rule,
            finding_type="broad_allow",
            severity=severity,
            evidence={**evidence, "has_logging": rule.has_logging},
            recommended_action=recommendation,
            review_note="Broad allow rule should be narrowed on source, destination, or service and logged appropriately.",
        )
        finding.evidence.update(advise_broad_rule(rule, finding))
        findings.append(finding)
    return findings
