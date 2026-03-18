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


def _conflict_classification(earlier: RuleRecord, later: RuleRecord, analysis: AnalysisConfig) -> str:
    earlier_action = earlier.action.lower()
    later_action = later.action.lower()
    if earlier_action == "accept" and later_action in {"drop", "reject"}:
        return "allow_then_deny_exception" if _is_broad(earlier, analysis) else "same_scope_policy_conflict"
    if earlier_action in {"drop", "reject"} and later_action == "accept":
        return "deny_then_allow_override"
    return "same_scope_policy_conflict"


def _is_broad(rule: RuleRecord, analysis: AnalysisConfig) -> bool:
    broad_axes = sum([rule.has_any_source, rule.has_any_destination, rule.has_any_service])
    return (
        broad_axes > 1
        or rule.has_any_service
        or rule.source_count >= analysis.broad_group_size_threshold
        or rule.destination_count >= analysis.broad_group_size_threshold
        or rule.service_count >= analysis.broad_group_size_threshold
    )


def _axis_tokens(scope, axis: str) -> set[str]:
    if axis == "source":
        return set(scope.source_networks or scope.source_names)
    if axis == "destination":
        return set(scope.destination_networks or scope.destination_names)
    if axis == "service":
        return set(scope.service_ranges or scope.service_names)
    if axis == "application":
        return set(scope.application_names)
    if axis == "install_on":
        return set(scope.install_on_names)
    return set()


def _axis_overlaps(left_scope, right_scope, axis: str) -> bool:
    left_tokens = _axis_tokens(left_scope, axis)
    right_tokens = _axis_tokens(right_scope, axis)
    if axis == "source" and (left_scope.source_any or right_scope.source_any):
        return True
    if axis == "destination" and (left_scope.destination_any or right_scope.destination_any):
        return True
    if axis == "service" and (left_scope.service_any or right_scope.service_any):
        return True
    if not left_tokens or not right_tokens:
        return True
    return bool(left_tokens & right_tokens)


def _merge_like(earlier: RuleRecord, later: RuleRecord) -> tuple[bool, dict[str, object]]:
    if earlier.action.lower() != later.action.lower():
        return False, {}
    if earlier.package_name != later.package_name or earlier.layer_name != later.layer_name:
        return False, {}
    if abs(earlier.rule_number - later.rule_number) > 5:
        return False, {}

    left_scope = build_effective_scope(earlier)
    right_scope = build_effective_scope(later)
    identical_axes: list[str] = []
    differing_axes: list[str] = []

    for axis in ("source", "destination", "service", "application", "install_on"):
        left_tokens = _axis_tokens(left_scope, axis)
        right_tokens = _axis_tokens(right_scope, axis)
        if left_tokens == right_tokens:
            identical_axes.append(axis)
            continue
        differing_axes.append(axis)

    if len(differing_axes) != 1:
        return False, {}

    differing_axis = differing_axes[0]
    left_tokens = _axis_tokens(left_scope, differing_axis)
    right_tokens = _axis_tokens(right_scope, differing_axis)
    residual = _residual_differences(later, earlier)
    reverse_residual = _residual_differences(earlier, later)
    residual_count = len(residual.get(f"{differing_axis}_only_in_rule", [])) + len(
        reverse_residual.get(f"{differing_axis}_only_in_rule", [])
    )
    if residual_count > 4:
        return False, {}
    if left_tokens and right_tokens and len(left_tokens | right_tokens) > 4:
        return False, {}

    return True, {
        "merge_strategy": f"{differing_axis}_consolidation",
        "identical_axes": identical_axes,
        "differing_axes": differing_axes,
    }


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

            if analysis.enable_shadow_candidates and overlaps and earlier.action.lower() == rule.action.lower() and 3 <= len(axes) < 5:
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
                conflict_classification = _conflict_classification(earlier, rule, analysis)
                conflict_rationale = {
                    "allow_then_deny_exception": "Broad earlier allow overlaps a later deny-like exception and should be reviewed for intended exception handling.",
                    "deny_then_allow_override": "Earlier deny-like rule overlaps a later allow override and may indicate risky bypass logic.",
                    "same_scope_policy_conflict": "Earlier rule overlaps the later rule but applies a different action.",
                }[conflict_classification]
                evidence = _relation_evidence(
                    rule,
                    earlier,
                    "conflicting_overlap",
                    axes,
                    conflict_rationale,
                )
                evidence.update(
                    {
                        "earlier_action": earlier.action,
                        "later_action": rule.action,
                        "conflict_classification": conflict_classification,
                    }
                )
                findings.append(
                    make_finding(
                        rule,
                        finding_type="conflicting_overlap",
                        severity="high",
                        evidence=evidence,
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

            mergeable, merge_details = _merge_like(earlier, rule)
            if analysis.enable_duplicate_candidates and mergeable:
                evidence = _relation_evidence(
                    rule,
                    earlier,
                    "merge_candidates",
                    axes,
                    "Nearby rules share most normalized scope dimensions and look mergeable.",
                )
                evidence.update(merge_details)
                findings.append(
                    make_finding(
                        rule,
                        finding_type="merge_candidates",
                        severity="medium",
                        evidence=evidence,
                        recommended_action="MERGE_CANDIDATE",
                        review_note="Rules can likely be combined into a cleaner single rule after owner review.",
                    )
                )
        by_layer[key].append(rule)

    return findings
