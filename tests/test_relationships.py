from __future__ import annotations

from cp_review.analyzers.relationships import run
from cp_review.config import AnalysisConfig
from cp_review.models import RuleRecord, RuleReference


def _rule(
    *,
    uid: str,
    rule_number: int,
    action: str = "Accept",
    source: list[RuleReference] | None = None,
    destination: list[RuleReference] | None = None,
    service: list[RuleReference] | None = None,
    has_any_source: bool = False,
    has_any_destination: bool = False,
    has_any_service: bool = False,
) -> RuleRecord:
    return RuleRecord(
        package_name="Standard",
        layer_name="Network",
        rule_number=rule_number,
        rule_uid=uid,
        rule_name=uid,
        enabled=True,
        action=action,
        source=source or [RuleReference(name="10.0.0.10", type="host")],
        destination=destination or [RuleReference(name="10.0.1.10", type="host")],
        service=service or [RuleReference(name="https", type="service-tcp")],
        application_or_site=[],
        install_on=[],
        track="Log",
        comments="ok",
        hit_count=0,
        has_any_source=has_any_source,
        has_any_destination=has_any_destination,
        has_any_service=has_any_service,
        has_logging=True,
        has_comment=True,
        source_count=len(source or [RuleReference(name="10.0.0.10", type="host")]),
        destination_count=len(destination or [RuleReference(name="10.0.1.10", type="host")]),
        service_count=len(service or [RuleReference(name="https", type="service-tcp")]),
    )


def test_relationships_emit_exact_duplicate_and_full_shadow():
    earlier = _rule(uid="r1", rule_number=1)
    later = _rule(uid="r2", rule_number=2)

    findings = run([earlier, later], AnalysisConfig())
    finding_types = {finding.finding_type for finding in findings}

    assert "exact_duplicate" in finding_types


def test_relationships_emit_semantic_duplicate_for_equivalent_service_alias():
    earlier = _rule(uid="r1", rule_number=1, service=[RuleReference(name="https", type="service-tcp")])
    later = _rule(uid="r2", rule_number=2, service=[RuleReference(name="tcp_443", type="service-tcp")])

    findings = run([earlier, later], AnalysisConfig())

    assert any(finding.finding_type == "semantic_duplicate" for finding in findings)


def test_relationships_emit_shadow_and_conflicting_overlap():
    broad_accept = _rule(
        uid="r1",
        rule_number=1,
        source=[RuleReference(name="Any", type="CpmiAnyObject")],
        destination=[RuleReference(name="Any", type="CpmiAnyObject")],
        service=[RuleReference(name="Any", type="service-any")],
        has_any_source=True,
        has_any_destination=True,
        has_any_service=True,
    )
    later_specific = _rule(
        uid="r2",
        rule_number=2,
        source=[RuleReference(name="10.0.0.10", type="host")],
        destination=[RuleReference(name="10.0.1.10", type="host")],
        service=[RuleReference(name="https", type="service-tcp")],
    )
    later_drop = _rule(
        uid="r3",
        rule_number=3,
        action="Drop",
        source=[RuleReference(name="10.0.0.10", type="host")],
        destination=[RuleReference(name="10.0.1.10", type="host")],
        service=[RuleReference(name="https", type="service-tcp")],
    )

    findings = run([broad_accept, later_specific, later_drop], AnalysisConfig())
    finding_types = {finding.finding_type for finding in findings}

    assert "full_shadow" in finding_types
    assert "dead_rule_after_covering_rule" in finding_types
    assert "conflicting_overlap" in finding_types
    assert "exception_rule_misordered" in finding_types


def test_relationships_respect_duplicate_and_shadow_feature_flags():
    earlier = _rule(uid="r1", rule_number=1)
    later = _rule(uid="r2", rule_number=2)

    findings = run(
        [earlier, later],
        AnalysisConfig(enable_duplicate_candidates=False, enable_shadow_candidates=False),
    )

    assert findings == []


def test_relationships_use_expanded_group_members_for_shadow_detection():
    grouped = _rule(
        uid="r1",
        rule_number=1,
        source=[
            RuleReference(
                name="Src-Group",
                type="group",
                effective_members=["10.10.0.0/24", "10.10.0.10"],
                effective_networks=["10.10.0.0/24", "10.10.0.10/32"],
            )
        ],
        destination=[
            RuleReference(
                name="Dst-Group",
                type="group",
                effective_members=["10.20.0.20"],
                effective_networks=["10.20.0.20/32"],
            )
        ],
        service=[
            RuleReference(
                name="Svc-Group",
                type="service-group",
                effective_members=["https"],
                effective_services=["tcp:443-443"],
            )
        ],
    )
    specific = _rule(
        uid="r2",
        rule_number=2,
        source=[RuleReference(name="10.10.0.10", type="host")],
        destination=[RuleReference(name="10.20.0.20", type="host")],
        service=[RuleReference(name="tcp_443", type="service-tcp")],
    )

    findings = run([grouped, specific], AnalysisConfig())

    assert any(finding.finding_type == "full_shadow" for finding in findings)


def test_relationships_emit_partial_shadow_when_only_some_axes_are_covered():
    earlier = _rule(uid="r1", rule_number=1)
    later = _rule(uid="r2", rule_number=2)
    later.application_or_site = [RuleReference(name="Office365", type="application-site")]

    findings = run([earlier, later], AnalysisConfig())

    partial = next(finding for finding in findings if finding.finding_type == "partial_shadow")
    assert partial.evidence["coverage_axes"] == ["source", "destination", "service", "install_on"]
    assert partial.evidence["residual_differences"]["application_only_in_rule"] == ["office365"]


def test_relationships_merge_candidates_include_strategy_for_single_axis_consolidation():
    earlier = _rule(uid="r1", rule_number=1, source=[RuleReference(name="10.0.0.10", type="host")])
    later = _rule(uid="r2", rule_number=2, source=[RuleReference(name="10.0.0.11", type="host")])

    findings = run([earlier, later], AnalysisConfig())

    merge = next(finding for finding in findings if finding.finding_type == "merge_candidates")
    assert merge.evidence["merge_strategy"] == "source_consolidation"
    assert merge.evidence["differing_axes"] == ["source"]
