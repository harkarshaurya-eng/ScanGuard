"""Port scanning wrappers."""

from __future__ import annotations

import os

from scanguard.mcp.schemas import TargetType, ToolCategory, ToolDefinition, ToolExecutionInput
from scanguard.parsers.naabu_parser import parse_naabu_output
from scanguard.parsers.nmap_parser import parse_nmap_xml
from scanguard.tools.base import no_extra_args


def _nmap_basic_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["nmap", "-Pn", "-T3", "-sV", "--top-ports", "1000", "-oX", "-", input_data.target]


def _nmap_syn_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    geteuid = getattr(os, "geteuid", None)
    if os.name != "posix" or geteuid is None or geteuid() != 0:
        raise PermissionError("SYN scan requires root privileges on Kali Linux.")
    return ["nmap", "-Pn", "-T2", "-sS", "--top-ports", "1000", "-oX", "-", input_data.target]


def _naabu_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return [
        "naabu",
        "-host",
        input_data.target,
        "-top-ports",
        "100",
        "-rate",
        "50",
        "-json",
        "-exclude-cdn",
    ]


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
        ToolDefinition(
            name="naabu_top_ports",
            description="Probe the top 100 TCP ports with a low rate using naabu.",
            category=ToolCategory.active_safe,
            binary="naabu",
            input_schema={"target": "domain|ip"},
            requires_confirmation=True,
            command_builder=_naabu_command,
            parser=parse_naabu_output,
            timeout_seconds=300,
            rate_limit_seconds=60,
            allowed_target_types=[TargetType.domain, TargetType.ip],
        ),
    ]


