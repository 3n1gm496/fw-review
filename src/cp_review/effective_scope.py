"""Semantic scope helpers for rule-relationship analysis."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from cp_review.models import EffectiveScope, RuleRecord, RuleReference

ANY_TOKENS = {"any", "internet", "cpmi any object"}
COMMON_SERVICE_PORTS: dict[str, tuple[str, int, int]] = {
    "http": ("tcp", 80, 80),
    "https": ("tcp", 443, 443),
    "ssh": ("tcp", 22, 22),
    "dns": ("udp", 53, 53),
    "smtp": ("tcp", 25, 25),
    "ldap": ("tcp", 389, 389),
    "ldaps": ("tcp", 636, 636),
    "rdp": ("tcp", 3389, 3389),
}
SERVICE_RE = re.compile(r"^(?:(tcp|udp)[_:/-])?(\d{1,5})(?:[-:](\d{1,5}))?$", re.IGNORECASE)
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _norm(value: str) -> str:
    return value.strip().lower()


def _unique(values: Iterable[str]) -> list[str]:
    return sorted({value for value in values if value})


def _parse_network(value: str) -> IPNetwork | None:
    token = value.strip()
    try:
        if "/" in token:
            return ipaddress.ip_network(token, strict=False)
        return ipaddress.ip_network(ipaddress.ip_address(token).exploded, strict=False)
    except ValueError:
        return None


def _parse_service(reference: RuleReference) -> tuple[str, int, int] | None:
    token = _norm(reference.name)
    if token in ANY_TOKENS:
        return ("any", 0, 65535)
    if token in COMMON_SERVICE_PORTS:
        return COMMON_SERVICE_PORTS[token]
    match = SERVICE_RE.match(token)
    if match:
        proto = (match.group(1) or (reference.type or "tcp")).lower()
        start = int(match.group(2))
        end = int(match.group(3) or match.group(2))
        return (proto, start, end)
    return None


def _expanded_names(refs: list[RuleReference]) -> list[str]:
    return _unique(_norm(value) for ref in refs for value in [ref.name, *ref.effective_members])


def _expanded_networks(refs: list[RuleReference]) -> list[str]:
    return _unique(
        str(network)
        for ref in refs
        for token in [ref.name, *ref.effective_networks]
        for network in [_parse_network(token)]
        if network is not None
    )


def _expanded_service_ranges(refs: list[RuleReference]) -> list[str]:
    ranges = {
        token
        for ref in refs
        for token in ref.effective_services
        if token
    }
    for ref in refs:
        parsed = _parse_service(ref)
        if parsed is not None:
            proto, start, end = parsed
            ranges.add(f"{proto}:{start}-{end}")
    return sorted(ranges)


def build_effective_scope(rule: RuleRecord) -> EffectiveScope:
    """Build a serializable effective scope view for one rule."""
    source_names = _expanded_names(rule.source)
    destination_names = _expanded_names(rule.destination)
    service_names = _expanded_names(rule.service)
    application_names = _expanded_names(rule.application_or_site)
    install_on_names = _expanded_names(rule.install_on)
    return EffectiveScope(
        source_any=rule.has_any_source or any(name in ANY_TOKENS for name in source_names),
        destination_any=rule.has_any_destination or any(name in ANY_TOKENS for name in destination_names),
        service_any=rule.has_any_service or any(name in ANY_TOKENS for name in service_names),
        source_names=source_names,
        destination_names=destination_names,
        service_names=service_names,
        application_names=application_names,
        install_on_names=install_on_names,
        source_networks=_expanded_networks(rule.source),
        destination_networks=_expanded_networks(rule.destination),
        service_ranges=_expanded_service_ranges(rule.service),
    )


def _covers_names(
    covering_names: list[str],
    candidate_names: list[str],
    *,
    any_flag: bool = False,
    parsed_covering: list[IPNetwork] | None = None,
    parsed_candidate: list[IPNetwork] | None = None,
) -> bool:
    if not candidate_names:
        return True
    if any_flag:
        return True
    name_cover = set(covering_names).issuperset(candidate_names)
    if parsed_covering is None or parsed_candidate is None or not parsed_candidate:
        return name_cover
    parsed_cover = all(any(_network_contains(candidate, existing) for existing in parsed_covering) for candidate in parsed_candidate)
    unresolved_names = {name for name in candidate_names if _parse_network(name) is None}
    return parsed_cover and set(covering_names).issuperset(unresolved_names)


def _overlaps_names(
    left_names: list[str],
    right_names: list[str],
    *,
    left_any: bool = False,
    right_any: bool = False,
    left_networks: list[IPNetwork] | None = None,
    right_networks: list[IPNetwork] | None = None,
) -> bool:
    if left_any or right_any:
        return True
    if not left_names or not right_names:
        return True
    if set(left_names) & set(right_names):
        return True
    if left_networks and right_networks:
        return any(network_a.overlaps(network_b) for network_a in left_networks for network_b in right_networks)
    return False


def _network_contains(candidate: IPNetwork, existing: IPNetwork) -> bool:
    if isinstance(candidate, ipaddress.IPv4Network) and isinstance(existing, ipaddress.IPv4Network):
        return candidate.subnet_of(existing)
    if isinstance(candidate, ipaddress.IPv6Network) and isinstance(existing, ipaddress.IPv6Network):
        return candidate.subnet_of(existing)
    return False


def _parse_networks(values: list[str]) -> list[IPNetwork]:
    return [network for value in values for network in [_parse_network(value)] if network is not None]


def _parse_service_ranges(values: list[str]) -> list[tuple[str, int, int]]:
    parsed: list[tuple[str, int, int]] = []
    for value in values:
        proto, ports = value.split(":", maxsplit=1)
        start, end = ports.split("-", maxsplit=1)
        parsed.append((proto, int(start), int(end)))
    return parsed


def _covers_services(covering: EffectiveScope, candidate: EffectiveScope) -> bool:
    if not candidate.service_names:
        return True
    if covering.service_any:
        return True
    if set(covering.service_names).issuperset(candidate.service_names):
        return True
    parsed_covering = _parse_service_ranges(covering.service_ranges)
    parsed_candidate = _parse_service_ranges(candidate.service_ranges)
    if not parsed_candidate:
        return False
    for proto, start, end in parsed_candidate:
        if not any(existing_proto in {proto, "any"} and existing_start <= start and existing_end >= end for existing_proto, existing_start, existing_end in parsed_covering):
            return False
    return True


def _overlaps_services(left: EffectiveScope, right: EffectiveScope) -> bool:
    if left.service_any or right.service_any:
        return True
    if not left.service_names or not right.service_names:
        return True
    if set(left.service_names) & set(right.service_names):
        return True
    for proto_a, start_a, end_a in _parse_service_ranges(left.service_ranges):
        for proto_b, start_b, end_b in _parse_service_ranges(right.service_ranges):
            if proto_a not in {proto_b, "any"} and proto_b != "any":
                continue
            if start_a <= end_b and start_b <= end_a:
                return True
    return False


def scope_covers(covering_rule: RuleRecord, candidate_rule: RuleRecord) -> tuple[bool, list[str]]:
    """Return whether one rule semantically covers another and on which axes."""
    left = build_effective_scope(covering_rule)
    right = build_effective_scope(candidate_rule)
    axes: list[str] = []

    left_source_networks = _parse_networks(left.source_names)
    right_source_networks = _parse_networks(right.source_names)
    if _covers_names(
        left.source_names,
        right.source_names,
        any_flag=left.source_any,
        parsed_covering=left_source_networks,
        parsed_candidate=right_source_networks,
    ):
        axes.append("source")

    left_destination_networks = _parse_networks(left.destination_names)
    right_destination_networks = _parse_networks(right.destination_names)
    if _covers_names(
        left.destination_names,
        right.destination_names,
        any_flag=left.destination_any,
        parsed_covering=left_destination_networks,
        parsed_candidate=right_destination_networks,
    ):
        axes.append("destination")

    if _covers_services(left, right):
        axes.append("service")

    if _covers_names(left.application_names, right.application_names):
        axes.append("application")

    # Empty install-on is treated as policy-wide coverage.
    if not left.install_on_names or _covers_names(left.install_on_names, right.install_on_names):
        axes.append("install_on")

    return len(axes) == 5, axes


def scope_equivalent(left_rule: RuleRecord, right_rule: RuleRecord) -> bool:
    """Return whether two rules are semantically equivalent."""
    left_covers, _ = scope_covers(left_rule, right_rule)
    right_covers, _ = scope_covers(right_rule, left_rule)
    return left_covers and right_covers


def scope_overlaps(left_rule: RuleRecord, right_rule: RuleRecord) -> bool:
    """Return whether two rules overlap semantically on all key dimensions."""
    left = build_effective_scope(left_rule)
    right = build_effective_scope(right_rule)

    source_overlap = _overlaps_names(
        left.source_names,
        right.source_names,
        left_any=left.source_any,
        right_any=right.source_any,
        left_networks=_parse_networks(left.source_names),
        right_networks=_parse_networks(right.source_names),
    )
    destination_overlap = _overlaps_names(
        left.destination_names,
        right.destination_names,
        left_any=left.destination_any,
        right_any=right.destination_any,
        left_networks=_parse_networks(left.destination_names),
        right_networks=_parse_networks(right.destination_names),
    )
    service_overlap = _overlaps_services(left, right)
    application_overlap = _overlaps_names(left.application_names, right.application_names)
    install_on_overlap = (
        not left.install_on_names
        or not right.install_on_names
        or bool(set(left.install_on_names) & set(right.install_on_names))
    )
    return all((source_overlap, destination_overlap, service_overlap, application_overlap, install_on_overlap))
