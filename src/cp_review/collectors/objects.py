"""Lazy object enrichment for rule references."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from cp_review.collectors import save_raw_json
from cp_review.config import AppConfig, RunPaths
from cp_review.exceptions import CheckPointApiError
from cp_review.models import DatasetWarning, RuleRecord, RuleReference


def _iter_rule_refs(rules: Iterable[RuleRecord]) -> Iterable[RuleReference]:
    for rule in rules:
        for bucket in (rule.source, rule.destination, rule.service, rule.application_or_site, rule.install_on):
            yield from bucket


def collect_referenced_objects(
    client: Any,
    settings: AppConfig,
    run_paths: RunPaths,
    rules: list[RuleRecord],
) -> tuple[dict[str, dict[str, Any]], list[DatasetWarning]]:
    """Fetch only unresolved referenced objects to keep enrichment lazy."""
    unresolved_uids = sorted(
        {
            ref.uid
            for ref in _iter_rule_refs(rules)
            if ref.uid and (not ref.type or ref.name == ref.uid)
        }
    )
    object_cache: dict[str, dict[str, Any]] = {}
    warnings: list[DatasetWarning] = []
    for uid in unresolved_uids:
        try:
            response = client.call_api("show-object", {"uid": uid, "details-level": "standard"})
        except CheckPointApiError as exc:
            warnings.append(
                DatasetWarning(
                    code="OBJECT_LOOKUP_FAILED",
                    message=f"show-object failed for unresolved reference {uid}: {exc}",
                    object_uid=uid,
                )
            )
            continue
        object_cache[uid] = response
        if settings.collection.save_raw:
            save_raw_json(run_paths.raw_dir / "objects" / f"{uid}.json", response)
    return object_cache, warnings
