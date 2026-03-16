from __future__ import annotations

from cp_review.compare import compare_findings


def test_compare_findings_returns_new_resolved_and_persisting():
    previous = [
        {"finding_type": "unused_rules", "rule_uid": "r1", "package_name": "P", "layer_name": "L", "rule_number": 1},
        {"finding_type": "no_log_rules", "rule_uid": "r2", "package_name": "P", "layer_name": "L", "rule_number": 2},
    ]
    current = [
        {"finding_type": "no_log_rules", "rule_uid": "r2", "package_name": "P", "layer_name": "L", "rule_number": 2},
        {"finding_type": "broad_allow", "rule_uid": "r3", "package_name": "P", "layer_name": "L", "rule_number": 3},
    ]

    result = compare_findings(previous, current)

    assert result["previous_count"] == 2
    assert result["current_count"] == 2
    assert result["new_count"] == 1
    assert result["resolved_count"] == 1
    assert result["persisting_count"] == 1
    assert result["new_findings"][0]["rule_uid"] == "r3"
    assert result["resolved_findings"][0]["rule_uid"] == "r1"
    assert result["persisting_findings"][0]["rule_uid"] == "r2"
