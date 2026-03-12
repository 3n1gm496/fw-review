"""Access-rulebase collection helpers."""

from __future__ import annotations

from typing import Any

from cp_review.collectors import save_raw_json
from cp_review.config import AppConfig, RunPaths
from cp_review.exceptions import CollectionError


def _layer_selector(layer: dict[str, Any]) -> dict[str, Any]:
    if layer.get("uid"):
        return {"uid": layer["uid"]}
    if layer.get("name"):
        return {"name": layer["name"]}
    raise CollectionError(f"Layer reference is missing both uid and name: {layer}")


def collect_access_rulebase_pages(
    client: Any,
    settings: AppConfig,
    run_paths: RunPaths,
    package_name: str,
    layer: dict[str, Any],
) -> list[dict[str, Any]]:
    """Collect a rulebase in paginated, light-detail pages."""
    pages: list[dict[str, Any]] = []
    offset = 0
    page_index = 0
    while True:
        payload = {
            **_layer_selector(layer),
            "offset": offset,
            "limit": settings.collection.page_limit,
            "details-level": "standard",
            "use-object-dictionary": False,
            "show-hits": settings.collection.collect_hitcount,
        }
        response = client.call_api("show-access-rulebase", payload)
        if settings.collection.save_raw:
            layer_token = layer.get("name", layer.get("uid", "layer")).replace("/", "_")
            save_raw_json(
                run_paths.raw_dir / "rulebase" / f"{package_name}__{layer_token}__page_{page_index:04d}.json",
                response,
            )
        pages.append(response)
        items = response.get("rulebase", [])
        if not items:
            break
        fetched = len(items)
        total = response.get("total")
        next_offset = offset + fetched
        if total is not None and next_offset >= int(total):
            break
        if fetched < settings.collection.page_limit:
            break
        if next_offset == offset:
            raise CollectionError(f"Pagination stalled for package={package_name} layer={layer}")
        offset = next_offset
        page_index += 1
    return pages
