"""Schemas for the local MCP-like tool system."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from scanguard.storage.models import ParsedToolOutput


class ToolCategory(StrEnum):
    passive = "passive"
    active_safe = "active_safe"
    active_careful = "active_careful"


class TargetType(StrEnum):
    domain = "domain"
    ip = "ip"
    url = "url"


class ToolExecutionInput(BaseModel):
    """Validated runtime input for a tool invocation."""

    target: str
    project_id: str
    extra_args: list[str] = Field(default_factory=list)
    wordlist: str | None = None
    severity_filter: list[str] = Field(default_factory=list)
    user_confirmed: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolDefinition(BaseModel):
    """Definition of a single runnable tool."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    description: str
    category: ToolCategory
    binary: str
    input_schema: dict[str, Any]
    requires_confirmation: bool
    command_builder: Callable[[ToolExecutionInput], list[str]]
    parser: Callable[[str, str], ParsedToolOutput]
    timeout_seconds: int
    rate_limit_seconds: int
    allowed_target_types: list[TargetType]
    dangerous_flags: list[str] = Field(default_factory=list)
    output_paths: list[str] = Field(default_factory=lambda: ["stdout", "stderr", "parsed"])
    notes: str | None = None


class ToolPlan(BaseModel):
    """Structured plan or proposal returned by the agent."""

    intent: str
    tool_name: str | None = None
    reason: str
    target: str | None = None
    requires_confirmation: bool = False
    risk_level: str = "passive"
    response_type: str
    answer: str | None = None


