"""Package discovery and end-to-end collection orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cp_review.collectors import save_raw_json
from cp_review.collectors.access_rulebase import collect_access_rulebase_pages
from cp_review.collectors.objects import collect_referenced_objects
from cp_review.config import AppConfig, RunPaths
from cp_review.models import DatasetWarning, NormalizedDataset
from cp_review.normalize.enrich import enrich_rules
from cp_review.normalize.flatten import flatten_access_rulebase_pages


def _extract_access_layers(package: dict[str, Any]) -> list[dict[str, Any]]:
    layers = package.get("access-layers") or package.get("access_layers") or []
    result: list[dict[str, Any]] = []
    for layer in layers:
        if isinstance(layer, dict):
            result.append(layer)
        elif isinstance(layer, str):
            result.append({"name": layer})
    return result


def discover_packages(client: Any, settings: AppConfig, run_paths: RunPaths) -> list[dict[str, Any]]:
    """Discover packages or load the selected package."""
    selected = settings.collection.package
    if selected and selected != "STANDARD_OR_SELECTED_PACKAGE":
        response = client.call_api("show-package", {"name": selected, "details-level": "standard"})
        if settings.collection.save_raw:
            save_raw_json(run_paths.raw_dir / "packages" / f"{selected}.json", response)
        return [response]

    offset = 0
    packages: list[dict[str, Any]] = []
    while True:
        response = client.call_api("show-packages", {"offset": offset, "limit": 100, "details-level": "standard"})
        if settings.collection.save_raw:
            save_raw_json(run_paths.raw_dir / "packages" / f"packages_{offset:04d}.json", response)
        page = response.get("packages", [])
        packages.extend(page)
        if not page:
            break
        total = response.get("total")
        offset += len(page)
        if total is not None and offset >= int(total):
            break
        if total is None and len(page) < 100:
            break
    return packages


def collect_policy_snapshot(client: Any, settings: AppConfig, run_paths: RunPaths) -> NormalizedDataset:
    """Collect, normalize, and enrich a policy snapshot."""
    packages = discover_packages(client, settings, run_paths)
    package_names = [pkg.get("name", pkg.get("uid", "unknown-package")) for pkg in packages]
    all_rules = []
    warnings: list[DatasetWarning] = []

    for package in packages:
        package_name = package.get("name", package.get("uid", "unknown-package"))
        layers = _extract_access_layers(package)
        if not layers:
            warnings.append(
                DatasetWarning(
                    code="NO_ACCESS_LAYERS",
                    message="Package does not expose access layers in the current API payload.",
                    package_name=package_name,
                )
            )
            continue
        for layer in layers:
            pages = collect_access_rulebase_pages(client, settings, run_paths, package_name, layer)
            rules, layer_warnings = flatten_access_rulebase_pages(package_name, layer, pages)
            all_rules.extend(rules)
            warnings.extend(layer_warnings)

    object_cache, object_warnings = collect_referenced_objects(client, settings, run_paths, all_rules)
    warnings.extend(object_warnings)
    enriched_rules = enrich_rules(all_rules, object_cache)
    return NormalizedDataset(
        generated_at=datetime.now(UTC),
        run_id=run_paths.run_id,
        source_host=settings.management.host,
        packages=package_names,
        rules=enriched_rules,
        warnings=warnings,
        raw_dir=run_paths.raw_dir,
    )
