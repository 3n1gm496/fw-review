from __future__ import annotations

import json
from pathlib import Path

from cp_review.analyzers import analyze_dataset
from cp_review.config import AnalysisConfig
from cp_review.models import NormalizedDataset
from cp_review.normalize.flatten import flatten_access_rulebase_pages


def _build_dataset() -> NormalizedDataset:
    fixture_path = Path(__file__).parent / "fixtures" / "sample_rulebase_page.json"
    page = json.loads(fixture_path.read_text(encoding="utf-8"))
    rules, warnings = flatten_access_rulebase_pages("Standard", {"name": "Network", "type": "access-layer"}, [page])
    return NormalizedDataset.model_validate(
        {
            "generated_at": "2026-03-12T00:00:00Z",
            "run_id": "test-run",
            "source_host": "mgmt.example.local",
            "packages": ["Standard"],
            "rules": [rule.model_dump(mode="json") for rule in rules],
            "warnings": [warning.model_dump(mode="json") for warning in warnings],
            "raw_dir": str(Path("/tmp/raw")),
        }
    )


def test_analyzers_emit_expected_finding_types():
    dataset = _build_dataset()
    findings = analyze_dataset(dataset, AnalysisConfig())
    finding_types = {finding.finding_type for finding in findings}

    assert "disabled_rules" in finding_types
    assert "unused_rules" in finding_types
    assert "broad_allow" in finding_types
    assert "no_log_rules" in finding_types
    assert "weak_documentation" in finding_types
    assert "shadow_candidates" in finding_types
    assert "high_risk_broad_usage" in finding_types
