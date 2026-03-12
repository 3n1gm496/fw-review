"""Rule enrichment helpers."""

from __future__ import annotations

from typing import Any

from cp_review.models import RuleRecord, RuleReference


def _enrich_reference(reference: RuleReference, object_cache: dict[str, dict[str, Any]]) -> RuleReference:
    if not reference.uid:
        return reference
    raw = object_cache.get(reference.uid)
    if not raw:
        return reference
    if reference.name == reference.uid and raw.get("name"):
        reference.name = raw["name"]
    if not reference.type and raw.get("type"):
        reference.type = raw["type"]
    return reference


def enrich_rules(rules: list[RuleRecord], object_cache: dict[str, dict[str, Any]]) -> list[RuleRecord]:
    """Fill missing reference names and types from fetched objects."""
    for rule in rules:
        for attr in ("source", "destination", "service", "application_or_site", "install_on"):
            refs = getattr(rule, attr)
            setattr(rule, attr, [_enrich_reference(ref, object_cache) for ref in refs])
    return rules
