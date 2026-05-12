"""DNS-focused tool wrappers."""

from __future__ import annotations

from scanguard.mcp.schemas import TargetType, ToolCategory, ToolDefinition, ToolExecutionInput
from scanguard.parsers.generic_parser import parse_lines_as_assets
from scanguard.tools.base import no_extra_args


def _dig_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["dig", "+short", input_data.target, "ANY"]


def _host_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["host", input_data.target]


def _nslookup_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["nslookup", input_data.target]


def build_dns_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="dns_records",
            description="Query DNS records using dig.",
            category=ToolCategory.passive,
            binary="dig",
            input_schema={"target": "domain"},
            requires_confirmation=False,
            command_builder=_dig_command,
            parser=lambda stdout, target: parse_lines_as_assets(stdout, target, "dns_record", "dns_records"),
            timeout_seconds=60,
            rate_limit_seconds=10,
            allowed_target_types=[TargetType.domain],
        ),
        ToolDefinition(
            name="host_lookup",
            description="Resolve a target using host.",
            category=ToolCategory.passive,
            binary="host",
            input_schema={"target": "domain|ip"},
            requires_confirmation=False,
            command_builder=_host_command,
            parser=lambda stdout, target: parse_lines_as_assets(stdout, target, "host_lookup", "host_lookup"),
            timeout_seconds=60,
            rate_limit_seconds=10,
            allowed_target_types=[TargetType.domain, TargetType.ip],
        ),
        ToolDefinition(
            name="nslookup_query",
            description="Query DNS via nslookup.",
            category=ToolCategory.passive,
            binary="nslookup",
            input_schema={"target": "domain|ip"},
            requires_confirmation=False,
            command_builder=_nslookup_command,
            parser=lambda stdout, target: parse_lines_as_assets(stdout, target, "nslookup_line", "nslookup_query"),
            timeout_seconds=60,
            rate_limit_seconds=10,
            allowed_target_types=[TargetType.domain, TargetType.ip],
        ),
    ]


