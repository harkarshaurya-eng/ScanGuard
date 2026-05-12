"""Port scanning wrappers."""

from __future__ import annotations

import os

from recon_ai.mcp.schemas import TargetType, ToolCategory, ToolDefinition, ToolExecutionInput
from recon_ai.parsers.nmap_parser import parse_nmap_xml
from recon_ai.tools.base import no_extra_args


def _nmap_basic_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["nmap", "-Pn", "-T3", "-sV", "--top-ports", "1000", "-oX", "-", input_data.target]


def _nmap_syn_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    geteuid = getattr(os, "geteuid", None)
    if os.name != "posix" or geteuid is None or geteuid() != 0:
        raise PermissionError("SYN scan requires root privileges on Kali Linux.")
    return ["nmap", "-Pn", "-T2", "-sS", "--top-ports", "1000", "-oX", "-", input_data.target]


def build_port_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="nmap_basic",
            description="Safe top-ports and version detection scan.",
            category=ToolCategory.active_safe,
            binary="nmap",
            input_schema={"target": "domain|ip"},
            requires_confirmation=True,
            command_builder=_nmap_basic_command,
            parser=parse_nmap_xml,
            timeout_seconds=600,
            rate_limit_seconds=90,
            allowed_target_types=[TargetType.domain, TargetType.ip],
        ),
        ToolDefinition(
            name="nmap_syn_safe",
            description="Root-only SYN scan with conservative timing and explicit confirmation.",
            category=ToolCategory.active_careful,
            binary="nmap",
            input_schema={"target": "domain|ip"},
            requires_confirmation=True,
            command_builder=_nmap_syn_command,
            parser=parse_nmap_xml,
            timeout_seconds=600,
            rate_limit_seconds=120,
            allowed_target_types=[TargetType.domain, TargetType.ip],
        ),
    ]

