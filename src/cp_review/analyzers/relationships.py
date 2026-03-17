"""Semantic rule-relationship analyzer."""

from __future__ import annotations

from collections import defaultdict

from cp_review.config import AnalysisConfig
from cp_review.effective_scope import build_effective_scope, scope_covers, scope_equivalent, scope_overlaps
from cp_review.models import RuleRecord
from cp_review.scoring.priority import make_finding


def _normalized_signature(rule: RuleRecord) -> tuple:
    return (
        rule.package_name,
        rule.layer_name,
        rule.action.lower(),
        tuple(sorted(ref.name.lower() for ref in rule.source)),
        tuple(sorted(ref.name.lower() for ref in rule.destination)),
        tuple(sorted(ref.name.lower() for ref in rule.service)),
        tuple(sorted(ref.name.lower() for ref in rule.application_or_site)),
        tuple(sorted(ref.name.lower() for ref in rule.install_on)),
        rule.enabled,
    )


def _residual_differences(rule: RuleRecord, other: RuleRecord) -> dict[str, list[str]]:
    left = build_effective_scope(other)
    right = build_effective_scope(rule)
    return {
        "source_only_in_rule": sorted(set(right.source_names) - set(left.source_names)),
        "destination_only_in_rule": sorted(set(right.destination_names) - set(left.destination_names)),
        "service_only_in_rule": sorted(set(right.service_names) - set(left.service_names)),
        "application_only_in_rule": sorted(set(right.application_names) - set(left.application_names)),
        "install_on_only_in_rule": sorted(set(right.install_on_names) - set(left.install_on_names)),
    }


def _relation_evidence(rule: RuleRecord, other: RuleRecord, relation_type: str, axes: list[str], rationale: str) -> dict[str, object]:
    return {
        "relation_type": relation_type,
        "related_rule_uids": [other.rule_uid],
        "related_rule_numbers": [other.rule_number],
        "covered_by_rule_uid": other.rule_uid,
        "covered_by_rule_number": other.rule_number,
        "covered_by_rule_name": other.rule_name,
        "coverage_axes": axes,
        "residual_differences": _residual_differences(rule, other),
        "rationale": rationale,
    }


def _is_broad(rule: RuleRecord, analysis: AnalysisConfig) -> bool:
    broad_axes = sum([rule.has_any_source, rule.has_any_destination, rule.has_any_service])
    return (
        broad_axes > 1
        or rule.has_any_service
        or rule.source_count >= analysis.broad_group_size_threshold
        or rule.destination_count >= analysis.broad_group_size_threshold
        or rule.service_count >= analysis.broad_group_size_threshold
    )


def _merge_like(earlier: RuleRecord, later: RuleRecord) -> bool:
    if earlier.action.lower() != later.action.lower():
        return False
    if earlier.package_name != later.package_name or earlier.layer_name != later.layer_name:
        return False
    if abs(earlier.rule_number - later.rule_number) > 5:
        return False
    same_destination = {ref.name for ref in earlier.destination} == {ref.name for ref in later.destination}
    same_service = {ref.name for ref in earlier.service} == {ref.name for ref in later.service}
    same_install = {ref.name for ref in earlier.install_on} == {ref.name for ref in later.install_on}
    same_application = {ref.name for ref in earlier.application_or_site} == {ref.name for ref in later.application_or_site}
    source_overlap = scope_overlaps(earlier, later)
    return same_destination and same_service and same_install and same_application and source_overlap


def run(rules: list[RuleRecord], analysis: AnalysisConfig) -> list:
    """Emit semantic relationship findings for cleanup and reordering."""
    findings = []
    by_layer: dict[tuple[str, str], list[RuleRecord]] = defaultdict(list)

    for rule in sorted(rules, key=lambda item: (item.package_name, item.layer_name, item.rule_number)):
        key = (rule.package_name, rule.layer_name)
        for earlier in by_layer[key][-250:]:
            exact_signature_match = _normalized_signature(earlier) == _normalized_signature(rule)
            equivalent = scope_equivalent(earlier, rule)
            covers, axes = scope_covers(earlier, rule)
            overlaps = scope_overlaps(earlier, rule)

            if analysis.enable_duplicate_candidates and exact_signature_match and earlier.action.lower() == rule.action.lower():
                findings.append(
                    make_finding(
                        rule,
                        finding_type="exact_duplicate",
                        severity="medium",
                        evidence=_relation_evidence(
                            rule,
                            earlier,
                            "exact_duplicate",
                            axes,
                            "Earlier rule has the same normalized signature in the same layer.",
                        ),
                        recommended_action="MERGE_DUPLICATE_OR_REMOVE_CANDIDATE",
                        review_note="Exact duplicate candidate should be merged or removed after owner validation.",
                    )
                )
                continue

            if analysis.enable_duplicate_candidates and equivalent and earlier.action.lower() == rule.action.lower():
                findings.append(
                    make_finding(
                        rule,
                        finding_type="semantic_duplicate",
                        severity="medium",
                        evidence=_relation_evidence(
                            rule,
                            earlier,
                            "semantic_duplicate",
                            axes,
                            "Earlier rule is semantically equivalent after scope normalization.",
                        ),
                        recommended_action="MERGE_CANDIDATE",
                        review_note="Semantically equivalent rule should be consolidated to reduce policy noise.",
                    )
                )
                continue

            if analysis.enable_shadow_candidates and covers and earlier.action.lower() == rule.action.lower():
                findings.append(
                    make_finding(
                        rule,
                        finding_type="full_shadow",
                        severity="medium",
                        evidence=_relation_evidence(
                            rule,
                            earlier,
                            "full_shadow",
                            axes,
                            "Earlier rule covers source, destination, service, application, and install-on for this rule.",
                        ),
                        recommended_action="REORDER_OR_REMOVE_SHADOWED_RULE",
                        review_note="Fully shadowed rule should be reviewed for removal or reordering.",
                    )
                )
                if (rule.hit_count or 0) == 0:
                    findings.append(
                        make_finding(
                            rule,
                            finding_type="dead_rule_after_covering_rule",
                            severity="medium",
                            evidence=_relation_evidence(
                                rule,
                                earlier,
                                "dead_rule_after_covering_rule",
                                axes,
                                "Rule is fully covered by an earlier rule and has zero observed hits.",
                            ),
                            recommended_action="REMOVE_CANDIDATE",
                            review_note="Rule looks unreachable in practice and is a strong cleanup candidate.",
                        )
                    )
                if earlier.action.lower() == "accept" and _is_broad(earlier, analysis) and _is_broad(rule, analysis) is False:
                    findings.append(
                        make_finding(
                            rule,
                            finding_type="broad_rule_before_specific_rule",
                            severity="high",
                            evidence=_relation_evidence(
                                rule,
                                earlier,
                                "broad_rule_before_specific_rule",
                                axes,
                                "Broad earlier rule likely reduces the readability or usefulness of a later specific rule.",
                            ),
                            recommended_action="REORDER_CANDIDATE",
                            review_note="Specific rule should be reviewed as a possible exception that belongs above the broad parent rule.",
                        )
                    )
                continue

            if analysis.enable_shadow_candidates and overlaps and earlier.action.lower() == rule.action.lower():
                findings.append(
                    make_finding(
                        rule,
                        finding_type="partial_shadow",
                        severity="medium",
                        evidence=_relation_evidence(
                            rule,
                            earlier,
                            "partial_shadow",
                            axes,
                            "Earlier rule overlaps materially with this rule but does not fully cover every axis.",
                        ),
                        recommended_action="REORDER_CANDIDATE",
                        review_note="Partial shadowing suggests policy ordering or consolidation work is needed.",
                    )
                )

            if analysis.enable_shadow_candidates and overlaps and earlier.action.lower() != rule.action.lower():
                findings.append(
                    make_finding(
                        rule,
                        finding_type="conflicting_overlap",
                        severity="high",
                        evidence=_relation_evidence(
                            rule,
                            earlier,
                            "conflicting_overlap",
                            axes,
                            "Earlier rule overlaps the later rule but applies a different action.",
                        ),
                        recommended_action="RESTRICT_SCOPE_AND_VALIDATE_ORDER",
                        review_note="Conflicting overlap should be reviewed with policy intent to avoid ambiguous outcomes.",
                    )
                )
                if earlier.action.lower() == "accept" and _is_broad(earlier, analysis):
                    findings.append(
                        make_finding(
                            rule,
                            finding_type="exception_rule_misordered",
                            severity="high",
                            evidence=_relation_evidence(
                                rule,
                                earlier,
                                "exception_rule_misordered",
                                axes,
                                "A later specific rule appears to behave like an exception behind a broad earlier allow rule.",
                            ),
                            recommended_action="REORDER_CANDIDATE",
                            review_note="Exception-like rule should be reviewed for placement above the broad parent rule.",
                        )
                    )

            if analysis.enable_duplicate_candidates and _merge_like(earlier, rule):
                findings.append(
                    make_finding(
                        rule,
                        finding_type="merge_candidates",
                        severity="medium",
                        evidence=_relation_evidence(
                            rule,
                            earlier,
                            "merge_candidates",
                            axes,
                            "Nearby rules share most normalized scope dimensions and look mergeable.",
                        ),
                        recommended_action="MERGE_CANDIDATE",
                        review_note="Rules can likely be combined into a cleaner single rule after owner review.",
                    )
                )
        by_layer[key].append(rule)

    return findings
