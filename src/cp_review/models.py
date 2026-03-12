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
