"""Persistence and domain models."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


class ProjectRecord(BaseModel):
    id: str
    target: str
    scope_file: str
    workspace_path: str
    status: str
    created_at: str


class ToolRunRecord(BaseModel):
    id: str
    project_id: str
    tool_name: str
    target: str
    command: str
    safety_category: str
    exit_code: int
    stdout_path: str
    stderr_path: str
    raw_json_path: str | None = None
    parsed_json_path: str | None = None
    requires_confirmation: bool
    created_at: str


class FindingRecord(BaseModel):
    id: str
    project_id: str
    title: str
    severity: Severity
    confidence: Confidence
    evidence: str
    affected_asset: str
    source_tool: str
    recommendation: str
    created_at: str


class ParsedFinding(BaseModel):
    title: str
    severity: Severity = "info"
    confidence: Confidence = "medium"
    evidence: str
    affected_asset: str
    source_tool: str
    recommendation: str


class ParsedAsset(BaseModel):
    asset_type: str
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ParsedToolOutput(BaseModel):
    summary: str
    assets: list[ParsedAsset] = Field(default_factory=list)
    findings: list[ParsedFinding] = Field(default_factory=list)
    raw_observations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReportArtifact(BaseModel):
    format: Literal["markdown", "html", "json"]
    path: Path
    created_at: str

