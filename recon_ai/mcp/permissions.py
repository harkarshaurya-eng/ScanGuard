"""Permission checks for tool execution."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

from recon_ai.mcp.schemas import TargetType, ToolCategory, ToolDefinition
from recon_ai.utils.validators import normalize_target


@dataclass(slots=True)
class PermissionDecision:
    allowed: bool
    reason: str
    target_type: TargetType | None = None


def determine_target_type(target: str) -> TargetType:
    """Classify a user-supplied target."""
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return TargetType.url
    normalized = normalize_target(target)
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return TargetType.domain
    return TargetType.ip


def evaluate_tool_permission(
    tool: ToolDefinition,
    target: str,
    auto_safe: bool,
    user_confirmed: bool,
) -> PermissionDecision:
    """Check whether a tool may run against a target right now."""
    target_type = determine_target_type(target)
    if target_type not in tool.allowed_target_types:
        return PermissionDecision(
            allowed=False,
            reason=f"Tool {tool.name} does not support target type {target_type.value}.",
            target_type=target_type,
        )
    if tool.requires_confirmation and not user_confirmed:
        if tool.category == ToolCategory.active_safe and auto_safe:
            return PermissionDecision(True, "Auto-safe execution permitted.", target_type)
        return PermissionDecision(False, f"Tool {tool.name} requires explicit confirmation.", target_type)
    return PermissionDecision(True, "Tool execution allowed.", target_type)

