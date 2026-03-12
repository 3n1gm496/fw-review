"""Flatten nested Access Control rulebases into canonical rows."""

from __future__ import annotations

from typing import Any

from cp_review.collectors.hitcount import extract_hit_data
from cp_review.models import DatasetWarning, RuleRecord, RuleReference

ANY_MARKERS = {"any", "cpmi any object", "internet"}
LOG_MARKERS = {"log", "alert", "detailed log", "account", "extended log"}


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return str(value.get("name") or value.get("uid") or value)
    return str(value)


def _normalize_ref_list(value: Any) -> list[RuleReference]:
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    refs: list[RuleReference] = []
    for item in value:
        if isinstance(item, dict):
            refs.append(
                RuleReference(
                    uid=item.get("uid"),
                    name=item.get("name") or item.get("uid") or "unknown",
                    type=item.get("type"),
                )
            )
        else:
            refs.append(RuleReference(name=str(item)))
    return refs


def _has_any(refs: list[RuleReference]) -> bool:
    return any((ref.name or "").strip().lower() in ANY_MARKERS for ref in refs)


def _has_logging(track: str) -> bool:
    return any(marker in track.lower() for marker in LOG_MARKERS)


def _extract_track(rule_payload: dict[str, Any]) -> str:
    track = rule_payload.get("track")
    if isinstance(track, dict):
        return _normalize_text(track.get("type") or track.get("name") or track)
    return _normalize_text(track)


def _extract_action(rule_payload: dict[str, Any]) -> str:
    action = rule_payload.get("action")
    if isinstance(action, dict):
        return _normalize_text(action.get("name") or action)
    return _normalize_text(action)


def _build_rule_record(
    package_name: str,
    layer: dict[str, Any],
    rule_payload: dict[str, Any],
    section_path: list[str],
    fallback_rule_number: int,
) -> RuleRecord:
    source = _normalize_ref_list(rule_payload.get("source"))
    destination = _normalize_ref_list(rule_payload.get("destination"))
    service = _normalize_ref_list(rule_payload.get("service"))
    applications = _normalize_ref_list(rule_payload.get("application-site") or rule_payload.get("application_or_site"))
    install_on = _normalize_ref_list(rule_payload.get("install-on") or rule_payload.get("install_on"))
    comments = _normalize_text(rule_payload.get("comments"))
    track = _extract_track(rule_payload)
    hit_count, hit_last_date = extract_hit_data(rule_payload)
    inline_layer = None
    if isinstance(rule_payload.get("inline-layer"), dict):
        inline_layer = rule_payload["inline-layer"].get("name") or rule_payload["inline-layer"].get("uid")
    elif rule_payload.get("inline-layer"):
        inline_layer = _normalize_text(rule_payload.get("inline-layer"))
    unsupported: list[str] = []
    if rule_payload.get("inline-layer"):
        unsupported.append("inline-layer")
    return RuleRecord(
        package_name=package_name,
        layer_name=layer.get("name", layer.get("uid", "unknown-layer")),
        layer_type=layer.get("type"),
        section_path=" / ".join(filter(None, section_path)),
        rule_number=int(rule_payload.get("rule-number") or rule_payload.get("rule_number") or fallback_rule_number),
        rule_uid=rule_payload.get("uid", f"generated-{fallback_rule_number}"),
        rule_name=_normalize_text(rule_payload.get("name")) or f"Rule {fallback_rule_number}",
        enabled=bool(rule_payload.get("enabled", True)),
        action=_extract_action(rule_payload),
        source=source,
        destination=destination,
        service=service,
        application_or_site=applications,
        install_on=install_on,
        track=track,
        comments=comments,
        hit_count=hit_count,
        hit_last_date=hit_last_date,
        has_any_source=_has_any(source),
        has_any_destination=_has_any(destination),
        has_any_service=_has_any(service),
        has_logging=_has_logging(track),
        has_comment=bool(comments.strip()),
        source_count=len(source),
        destination_count=len(destination),
        service_count=len(service),
        inline_layer=inline_layer,
        unsupported_features=unsupported,
        original_rule=rule_payload,
    )


def _flatten_nodes(
    package_name: str,
    layer: dict[str, Any],
    nodes: list[dict[str, Any]],
    section_path: list[str],
    rules: list[RuleRecord],
    warnings: list[DatasetWarning],
) -> None:
    for node in nodes:
        node_type = node.get("type", "access-rule")
        if node_type == "access-section":
            section_name = _normalize_text(node.get("name")) or "Unnamed Section"
            child_nodes = node.get("rulebase", [])
            _flatten_nodes(package_name, layer, child_nodes, [*section_path, section_name], rules, warnings)
            continue
        if node.get("rulebase") and node_type != "access-rule":
            warnings.append(
                DatasetWarning(
                    code="UNSUPPORTED_RULEBASE_NODE",
                    message=f"Unsupported rulebase node type: {node_type}",
                    package_name=package_name,
                    layer_name=layer.get("name"),
                    rule_uid=node.get("uid"),
                )
            )
            continue
        rule = _build_rule_record(package_name, layer, node, section_path, len(rules) + 1)
        rules.append(rule)
        if rule.inline_layer:
            warnings.append(
                DatasetWarning(
                    code="INLINE_LAYER_PRESENT",
                    message="Rule references an inline layer and was preserved with a marker for manual review.",
                    package_name=package_name,
                    layer_name=layer.get("name"),
                    rule_uid=rule.rule_uid,
                )
            )


def flatten_access_rulebase_pages(
    package_name: str,
    layer: dict[str, Any],
    pages: list[dict[str, Any]],
) -> tuple[list[RuleRecord], list[DatasetWarning]]:
    """Flatten paginated rulebase responses into canonical rule rows."""
    rules: list[RuleRecord] = []
    warnings: list[DatasetWarning] = []
    for page in pages:
        nodes = page.get("rulebase", [])
        _flatten_nodes(package_name, layer, nodes, [], rules, warnings)
    return rules, warnings
