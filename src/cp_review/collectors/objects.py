"""Lazy object enrichment for rule references."""

from __future__ import annotations

from typing import Any, Iterable

from cp_review.collectors import save_raw_json
from cp_review.config import AppConfig, RunPaths
from cp_review.models import RuleRecord, RuleReference


def _iter_rule_refs(rules: Iterable[RuleRecord]) -> Iterable[RuleReference]:
    for rule in rules:
        for bucket in (rule.source, rule.destination, rule.service, rule.application_or_site, rule.install_on):
            yield from bucket


def collect_referenced_objects(
    client: Any,
    settings: AppConfig,
    run_paths: RunPaths,
    rules: list[RuleRecord],
) -> dict[str, dict[str, Any]]:
    """Fetch only unresolved referenced objects to keep enrichment lazy."""
    unresolved_uids = sorted(
        {
            ref.uid
            for ref in _iter_rule_refs(rules)
            if ref.uid and (not ref.type or ref.name == ref.uid)
        }
    )
    object_cache: dict[str, dict[str, Any]] = {}
    for uid in unresolved_uids:
        response = client.call_api("show-object", {"uid": uid, "details-level": "standard"})
        object_cache[uid] = response
        if settings.collection.save_raw:
            save_raw_json(run_paths.raw_dir / "objects" / f"{uid}.json", response)
    return object_cache
