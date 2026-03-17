"""Analyzer orchestration."""

from __future__ import annotations

from cp_review.analyzers import (
    broad_allow,
    disabled_rules,
    high_risk_broad_usage,
    no_log_rules,
    relationships,
    unused_rules,
    weak_documentation,
)
from cp_review.config import AnalysisConfig
from cp_review.models import FindingRecord, NormalizedDataset


def analyze_dataset(dataset: NormalizedDataset, analysis: AnalysisConfig) -> list[FindingRecord]:
    """Run enabled analyzers against a normalized dataset."""
    findings: list[FindingRecord] = []
    findings.extend(disabled_rules.run(dataset.rules))
    findings.extend(unused_rules.run(dataset.rules, analysis))
    findings.extend(broad_allow.run(dataset.rules, analysis))
    findings.extend(no_log_rules.run(dataset.rules, analysis))
    findings.extend(weak_documentation.run(dataset.rules))
    findings.extend(relationships.run(dataset.rules, analysis))
    findings.extend(high_risk_broad_usage.run(dataset.rules, analysis))
    return sorted(
        findings,
        key=lambda item: (item.risk_score, item.cleanup_confidence, item.package_name, item.layer_name, item.rule_number),
        reverse=True,
    )
