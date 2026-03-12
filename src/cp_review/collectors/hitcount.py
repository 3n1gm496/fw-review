"""Helpers for extracting hit-count data from uncertain API payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _parse_datetime(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def extract_hit_data(rule_payload: dict[str, Any]) -> tuple[int | None, datetime | None]:
    """Extract hit-count fields from a rule payload."""
    candidates: list[Any] = [
        rule_payload.get("hits"),
        rule_payload.get("hit-count"),
        rule_payload.get("hit_count"),
        rule_payload.get("meta-info", {}).get("hits") if isinstance(rule_payload.get("meta-info"), dict) else None,
    ]
    for candidate in candidates:
        if isinstance(candidate, int):
            return candidate, None
        if isinstance(candidate, dict):
            count = candidate.get("value")
            count = candidate.get("hit-count") if count is None else count
            count = candidate.get("count") if count is None else count
            last = candidate.get("last-date") or candidate.get("last-hit") or candidate.get("last_date") or candidate.get("last_hit")
            if count is not None:
                try:
                    return int(count), _parse_datetime(last)
                except (TypeError, ValueError):
                    return None, _parse_datetime(last)
    return None, None
