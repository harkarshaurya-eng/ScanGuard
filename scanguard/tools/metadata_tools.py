"""Passive metadata enumeration wrappers."""

from __future__ import annotations

from scanguard.mcp.schemas import TargetType, ToolCategory, ToolDefinition, ToolExecutionInput
from scanguard.parsers.generic_parser import parse_lines_as_assets
from scanguard.tools.base import no_extra_args


def _theharvester_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["theHarvester", "-d", input_data.target, "-b", "all"]


def build_metadata_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="theharvester_passive",
            description="Collect passive metadata and OSINT indicators with theHarvester.",
            category=ToolCategory.passive,
            binary="theHarvester",
            input_schema={"target": "domain"},
            requires_confirmation=False,
            command_builder=_theharvester_command,
            parser=lambda stdout, target: parse_lines_as_assets(stdout, target, "metadata_line", "theharvester_passive"),
            timeout_seconds=300,
            rate_limit_seconds=60,
            allowed_target_types=[TargetType.domain],
        )
    ]

