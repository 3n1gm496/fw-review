from __future__ import annotations

import json
from pathlib import Path

from cp_review.normalize.flatten import flatten_access_rulebase_pages


def test_flatten_access_rulebase_preserves_sections_and_flags():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_rulebase_page.json"
    page = json.loads(fixture_path.read_text(encoding="utf-8"))
    rules, warnings = flatten_access_rulebase_pages(
        "Standard",
        {"name": "Network", "type": "access-layer"},
        [page],
    )

    assert len(rules) == 4
    assert rules[0].section_path == "User Access"
    assert rules[0].enabled is False
    assert rules[1].has_any_source is True
    assert rules[1].has_any_destination is True
    assert rules[1].has_any_service is True
    assert rules[1].has_logging is False
    assert warnings == []
