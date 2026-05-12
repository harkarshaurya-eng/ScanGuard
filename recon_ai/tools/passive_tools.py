"""Passive intelligence tool wrappers."""

from __future__ import annotations

from recon_ai.mcp.schemas import TargetType, ToolCategory, ToolDefinition, ToolExecutionInput
from recon_ai.parsers.generic_parser import parse_lines_as_assets
from recon_ai.tools.base import no_extra_args


def _whois_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["whois", input_data.target]


def build_passive_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="whois_lookup",
            description="Collect WHOIS registration data for a domain.",
            category=ToolCategory.passive,
            binary="whois",
            input_schema={"target": "domain"},
            requires_confirmation=False,
            command_builder=_whois_command,
            parser=lambda stdout, target: parse_lines_as_assets(stdout, target, "whois_line", "whois_lookup"),
            timeout_seconds=90,
            rate_limit_seconds=15,
            allowed_target_types=[TargetType.domain],
        )
    ]

