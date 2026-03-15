from __future__ import annotations

from cp_review.collectors.hitcount import extract_hit_data


def test_extract_hit_data_reads_integer_fields():
    count, last_hit = extract_hit_data({"hits": 12})
    assert count == 12
    assert last_hit is None


def test_extract_hit_data_reads_nested_fields():
    count, last_hit = extract_hit_data({"hit-count": {"value": "7", "last-date": "2026-03-10T11:22:33Z"}})
    assert count == 7
    assert last_hit is not None
    assert last_hit.isoformat() == "2026-03-10T11:22:33+00:00"


def test_extract_hit_data_handles_invalid_count():
    count, last_hit = extract_hit_data({"hit-count": {"value": "abc", "last-date": "2026-03-10T11:22:33Z"}})
    assert count is None
    assert last_hit is not None
