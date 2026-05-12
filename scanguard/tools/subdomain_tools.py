"""Subdomain discovery wrappers."""

from __future__ import annotations

from scanguard.mcp.schemas import TargetType, ToolCategory, ToolDefinition, ToolExecutionInput
from scanguard.parsers.generic_parser import parse_lines_as_assets
from scanguard.tools.base import no_extra_args


def _subfinder_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["subfinder", "-silent", "-d", input_data.target]


def _amass_passive_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["amass", "enum", "-passive", "-norecursive", "-d", input_data.target]


def build_subdomain_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="subfinder_passive",
            description="Passive subdomain enumeration with subfinder.",
            category=ToolCategory.passive,
            binary="subfinder",
            input_schema={"target": "domain"},
            requires_confirmation=False,
            command_builder=_subfinder_command,
            parser=lambda stdout, target: parse_lines_as_assets(stdout, target, "subdomain", "subfinder_passive"),
            timeout_seconds=180,
            rate_limit_seconds=30,
            allowed_target_types=[TargetType.domain],
        ),
        ToolDefinition(
            name="amass_passive",
            description="Passive subdomain enumeration with amass.",
            category=ToolCategory.passive,
            binary="amass",
            input_schema={"target": "domain"},
            requires_confirmation=False,
            command_builder=_amass_passive_command,
            parser=lambda stdout, target: parse_lines_as_assets(stdout, target, "subdomain", "amass_passive"),
            timeout_seconds=300,
            rate_limit_seconds=45,
            allowed_target_types=[TargetType.domain],
        ),
    ]


