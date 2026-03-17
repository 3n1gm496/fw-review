"""Rule enrichment helpers."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from cp_review.models import RuleRecord, RuleReference

SERVICE_PORT_RE = re.compile(r"^(?:(tcp|udp)[_:/-])?(\d{1,5})(?:[-:](\d{1,5}))?$", re.IGNORECASE)


def _network_tokens(raw: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    if raw.get("ipv4-address"):
        tokens.append(f"{raw['ipv4-address']}/32")
    if raw.get("ipv6-address"):
        tokens.append(f"{raw['ipv6-address']}/128")
    if raw.get("subnet4"):
        subnet = str(raw["subnet4"])
        if raw.get("mask-length4") is not None:
            tokens.append(f"{subnet}/{raw['mask-length4']}")
        elif raw.get("subnet-mask"):
            network = ipaddress.ip_network(f"{subnet}/{raw['subnet-mask']}", strict=False)
            tokens.append(str(network))
    if raw.get("subnet6") and raw.get("mask-length6") is not None:
        tokens.append(f"{raw['subnet6']}/{raw['mask-length6']}")
    return sorted({token for token in tokens if token})


def _service_tokens(raw: dict[str, Any]) -> list[str]:
    raw_type = str(raw.get("type", "")).lower()
    port = raw.get("port") or raw.get("port-range") or raw.get("port_range")
    if port:
        match = SERVICE_PORT_RE.match(str(port).strip())
        if match:
            proto = (match.group(1) or ("udp" if "udp" in raw_type else "tcp")).lower()
            start = int(match.group(2))
            end = int(match.group(3) or match.group(2))
            return [f"{proto}:{start}-{end}"]
    if "service-any" in raw_type:
        return ["any:0-65535"]
    return []


def _member_refs(raw: dict[str, Any]) -> list[dict[str, Any]]:
    members = raw.get("members") or raw.get("member") or []
    if not isinstance(members, list):
        members = [members]
    return [item for item in members if isinstance(item, dict)]


def _expand_member_names(raw: dict[str, Any], object_cache: dict[str, dict[str, Any]], seen: set[str]) -> list[str]:
    names: set[str] = set()
    for member in _member_refs(raw):
        uid = str(member.get("uid", ""))
        candidate = object_cache.get(uid, member)
        member_name = candidate.get("name") or member.get("name") or uid
        if member_name:
            names.add(str(member_name))
        if uid and uid not in seen:
            seen.add(uid)
            names.update(_expand_member_names(candidate, object_cache, seen))
    return sorted(names)


def _expand_networks(raw: dict[str, Any], object_cache: dict[str, dict[str, Any]], seen: set[str]) -> list[str]:
    networks = set(_network_tokens(raw))
    for member in _member_refs(raw):
        uid = str(member.get("uid", ""))
        candidate = object_cache.get(uid, member)
        networks.update(_network_tokens(candidate))
        if uid and uid not in seen:
            seen.add(uid)
            networks.update(_expand_networks(candidate, object_cache, seen))
    return sorted(networks)


def _expand_services(raw: dict[str, Any], object_cache: dict[str, dict[str, Any]], seen: set[str]) -> list[str]:
    services = set(_service_tokens(raw))
    for member in _member_refs(raw):
        uid = str(member.get("uid", ""))
        candidate = object_cache.get(uid, member)
        services.update(_service_tokens(candidate))
        if uid and uid not in seen:
            seen.add(uid)
            services.update(_expand_services(candidate, object_cache, seen))
    return sorted(services)


def _enrich_reference(reference: RuleReference, object_cache: dict[str, dict[str, Any]]) -> RuleReference:
    if not reference.uid:
        return reference
    raw = object_cache.get(reference.uid)
    if not raw:
        return reference
    if reference.name == reference.uid and raw.get("name"):
        reference.name = str(raw["name"])
    if not reference.type and raw.get("type"):
        reference.type = str(raw["type"])
    reference.effective_members = _expand_member_names(raw, object_cache, {reference.uid})
    reference.effective_networks = _expand_networks(raw, object_cache, {reference.uid})
    reference.effective_services = _expand_services(raw, object_cache, {reference.uid})
    return reference


def enrich_rules(rules: list[RuleRecord], object_cache: dict[str, dict[str, Any]]) -> list[RuleRecord]:
    """Fill missing reference names/types and propagate recursive object semantics."""
    for rule in rules:
        for attr in ("source", "destination", "service", "application_or_site", "install_on"):
            refs = getattr(rule, attr)
            setattr(rule, attr, [_enrich_reference(ref, object_cache) for ref in refs])
    return rules
