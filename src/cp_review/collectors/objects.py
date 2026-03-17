"""Lazy object enrichment for rule references."""

from __future__ import annotations

from collections import deque
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


def _member_uids(payload: dict[str, Any]) -> set[str]:
    members = payload.get("members") or payload.get("member") or []
    if not isinstance(members, list):
        members = [members]
    result: set[str] = set()
    for item in members:
        if isinstance(item, dict) and item.get("uid"):
            result.add(str(item["uid"]))
        elif isinstance(item, str):
            result.add(item)
    return result


def merge_object_dictionary_pages(pages: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Collect object-dictionary payloads embedded in rulebase pages."""
    cache: dict[str, dict[str, Any]] = {}
    for page in pages:
        dictionary = (
            page.get("objects-dictionary")
            or page.get("objects_dictionary")
            or page.get("object-dictionary")
            or []
        )
        if isinstance(dictionary, dict):
            dictionary = list(dictionary.values())
        if not isinstance(dictionary, list):
            continue
        for item in dictionary:
            if isinstance(item, dict) and item.get("uid"):
                cache[str(item["uid"])] = item
    return cache


def collect_referenced_objects(
    client: Any,
    settings: AppConfig,
    run_paths: RunPaths,
    rules: list[RuleRecord],
    initial_cache: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[DatasetWarning]]:
    """Fetch only unresolved referenced objects to keep enrichment lazy."""
    object_cache: dict[str, dict[str, Any]] = dict(initial_cache or {})
    unresolved_uids = deque(
        {
            ref.uid
            for ref in _iter_rule_refs(rules)
            if ref.uid and ((not ref.type or ref.name == ref.uid) or ref.uid not in object_cache)
        }
    )
    warnings: list[DatasetWarning] = []
    failed_uids: set[str] = set()
    while unresolved_uids:
        uid = unresolved_uids.popleft()
        if uid in object_cache or uid in failed_uids:
            continue
        try:
            response = client.call_api("show-object", {"uid": uid, "details-level": "standard"})
        except CheckPointApiError as exc:
            failed_uids.add(uid)
            warnings.append(
                DatasetWarning(
                    code="OBJECT_LOOKUP_FAILED",
                    message=f"show-object failed for unresolved reference {uid}: {exc}",
                    object_uid=uid,
                )
            )
            continue
        object_cache[uid] = response
        for member_uid in sorted(_member_uids(response)):
            if member_uid not in object_cache and member_uid not in failed_uids:
                unresolved_uids.append(member_uid)
        if settings.collection.save_raw:
            save_raw_json(run_paths.raw_dir / "objects" / f"{uid}.json", response)
    return object_cache, warnings
