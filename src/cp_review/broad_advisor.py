"""Broad-rule remediation advisor."""

from __future__ import annotations

from cp_review.models import FindingRecord, RuleRecord


def advise_broad_rule(rule: RuleRecord, finding: FindingRecord) -> dict[str, object]:
    """Return actionable guidance for broad allow rules."""
    candidates: list[dict[str, str | int]] = []
    if rule.has_any_source or rule.source_count > 10:
        candidates.append(
            {
                "axis": "source",
                "reason": "Source scope is overly broad or relies on Any/large groups.",
                "priority": 90 if rule.has_any_source else 70,
                "suggestion": "Replace Any or oversized source groups with known client networks or owner-scoped source objects.",
            }
        )
    if rule.has_any_destination or rule.destination_count > 10:
        candidates.append(
            {
                "axis": "destination",
                "reason": "Destination scope is too wide for a least-privilege policy.",
                "priority": 88 if rule.has_any_destination else 68,
                "suggestion": "Restrict destination to published application subnets, VIPs, or server groups.",
            }
        )
    if rule.has_any_service or rule.service_count > 6:
        candidates.append(
            {
                "axis": "service",
                "reason": "Service scope is generic and likely broader than the application requires.",
                "priority": 95 if rule.has_any_service else 72,
                "suggestion": "Replace Any service or wide service groups with explicit ports, service groups, or application signatures.",
            }
        )
    if not rule.has_logging:
        candidates.append(
            {
                "axis": "logging",
                "reason": "The rule is broad and lacks sufficient logging for safe cleanup decisions.",
                "priority": 80,
                "suggestion": "Enable logging before changing the rule so the cleanup can be validated with traffic evidence.",
            }
        )

    candidates.sort(key=lambda item: int(item.get("priority", 0)), reverse=True)
    primary = candidates[0]["axis"] if candidates else "service"
    return {
        "advisor_type": "broad_rule_advisor",
        "primary_restriction_axis": primary,
        "candidate_axes": candidates,
        "recommended_sequence": [str(item["axis"]) for item in candidates],
        "summary": (
            f"Restrict {primary} first."
            if candidates
            else "Start by restricting service scope and validating the rule with owner traffic evidence."
        ),
        "finding_risk_score": finding.risk_score,
    }
