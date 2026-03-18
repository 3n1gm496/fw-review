"""Core application data models."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class RuleReference(BaseModel):
    """Normalized representation of an object reference used by a rule."""

    uid: str | None = None
    name: str
    type: str | None = None
    effective_members: list[str] = Field(default_factory=list)
    effective_networks: list[str] = Field(default_factory=list)
    effective_services: list[str] = Field(default_factory=list)


class LogEvidence(BaseModel):
    """Targeted log evidence for a rule."""

    query: str
    count: int = 0
    sample_logs: list[dict[str, Any]] = Field(default_factory=list)
    collected_at: datetime


class RuleRecord(BaseModel):
    """Flattened Access Control rule record."""

    package_name: str
    layer_name: str
    layer_type: str | None = None
    section_path: str = ""
    rule_number: int
    rule_uid: str
    rule_name: str
    enabled: bool = True
    action: str
    source: list[RuleReference] = Field(default_factory=list)
    destination: list[RuleReference] = Field(default_factory=list)
    service: list[RuleReference] = Field(default_factory=list)
    application_or_site: list[RuleReference] = Field(default_factory=list)
    install_on: list[RuleReference] = Field(default_factory=list)
    track: str = ""
    comments: str = ""
    hit_count: int | None = None
    hit_last_date: datetime | None = None
    has_any_source: bool = False
    has_any_destination: bool = False
    has_any_service: bool = False
    has_logging: bool = False
    has_comment: bool = False
    source_count: int = 0
    destination_count: int = 0
    service_count: int = 0
    inline_layer: str | None = None
    unsupported_features: list[str] = Field(default_factory=list)
    original_rule: dict[str, Any] = Field(default_factory=dict)


class DatasetWarning(BaseModel):
    """Warning emitted during collection or normalization."""

    code: str
    message: str
    package_name: str | None = None
    layer_name: str | None = None
    rule_uid: str | None = None
    object_uid: str | None = None


class NormalizedDataset(BaseModel):
    """Canonical dataset produced by collection."""

    generated_at: datetime
    run_id: str
    source_host: str
    packages: list[str] = Field(default_factory=list)
    rules: list[RuleRecord] = Field(default_factory=list)
    log_evidence: dict[str, LogEvidence] = Field(default_factory=dict)
    warnings: list[DatasetWarning] = Field(default_factory=list)
    raw_dir: Path


class FindingRecord(BaseModel):
    """Technical finding emitted by an analyzer."""

    finding_type: str
    severity: str
    risk_score: int
    cleanup_confidence: int
    package_name: str
    layer_name: str
    rule_number: int
    rule_uid: str
    rule_name: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommended_action: str
    review_note: str


class EffectiveScope(BaseModel):
    """Semantically normalized scope representation for one rule."""

    source_any: bool = False
    destination_any: bool = False
    service_any: bool = False
    source_names: list[str] = Field(default_factory=list)
    destination_names: list[str] = Field(default_factory=list)
    service_names: list[str] = Field(default_factory=list)
    application_names: list[str] = Field(default_factory=list)
    install_on_names: list[str] = Field(default_factory=list)
    source_networks: list[str] = Field(default_factory=list)
    destination_networks: list[str] = Field(default_factory=list)
    service_ranges: list[str] = Field(default_factory=list)


class RuleRelation(BaseModel):
    """Relationship detected between two rules in the same policy layer."""

    relation_type: str
    package_name: str
    layer_name: str
    primary_rule_uid: str
    primary_rule_number: int
    secondary_rule_uid: str
    secondary_rule_number: int
    coverage_axes: list[str] = Field(default_factory=list)
    rationale: str


class ReviewQueueItem(BaseModel):
    """Actionable remediation item derived from one finding."""

    item_id: str
    run_id: str
    rule_uid: str
    package_name: str
    layer_name: str
    rule_number: int
    finding_type: str
    action_type: str
    priority: str
    confidence: int
    risk_score: int
    remove_confidence: int
    restrict_confidence: int
    reorder_confidence: int
    merge_confidence: int
    why_flagged: str
    related_rules: list[str] = Field(default_factory=list)
    suggested_next_step: str
    review_status: str = "new"
    owner: str = ""
    campaign: str = ""
    due_date: datetime | None = None


class ReviewStateEntry(BaseModel):
    """Persistent local review status for one queue item."""

    item_id: str
    rule_uid: str
    finding_type: str
    status: str = "new"
    owner: str = ""
    campaign: str = ""
    due_date: datetime | None = None
    notes: str = ""
    updated_at: datetime
