"""Helpers for autonomous recon planning."""

from __future__ import annotations

from scanguard.mcp.registry import ToolRegistry
from scanguard.mcp.schemas import AutonomousPlan, AutonomousStep


def build_offline_autonomous_plan(
    registry: ToolRegistry,
    *,
    auto_safe: bool,
    allow_careful: bool,
    max_steps: int,
) -> AutonomousPlan:
    """Build a deterministic safe plan when no AI provider is configured."""
    steps = [
        AutonomousStep(tool_name="whois_lookup", reason="Collect registration and ownership context."),
        AutonomousStep(tool_name="dns_records", reason="Collect core DNS records."),
        AutonomousStep(tool_name="dnsrecon_standard", reason="Expand standard DNS enumeration."),
        AutonomousStep(tool_name="subfinder_passive", reason="Identify passive subdomains."),
        AutonomousStep(tool_name="assetfinder_passive", reason="Broaden passive subdomain discovery."),
    ]
    if auto_safe:
        steps.extend(
            [
                AutonomousStep(tool_name="httpx_probe", reason="Identify reachable HTTP services and technologies."),
                AutonomousStep(tool_name="curl_headers", reason="Assess response headers for hardening gaps."),
                AutonomousStep(tool_name="waf_detection", reason="Identify any WAF or edge protection."),
                AutonomousStep(tool_name="naabu_top_ports", reason="Quickly identify exposed common TCP services."),
            ]
        )
    if allow_careful:
        steps.extend(
            [
                AutonomousStep(tool_name="nikto_basic", reason="Perform conservative web checks for obvious issues."),
                AutonomousStep(tool_name="nuclei_safe", reason="Run safe nuclei templates for additional findings."),
            ]
        )
    plan = AutonomousPlan(
        strategy="Offline safe baseline plan built from the local registry.",
        steps=steps,
        report_formats=["markdown", "html", "json"],
    )
    return sanitize_autonomous_plan(
        registry,
        plan,
        auto_safe=auto_safe,
        allow_careful=allow_careful,
        max_steps=max_steps,
    )


def sanitize_autonomous_plan(
    registry: ToolRegistry,
    plan: AutonomousPlan,
    *,
    auto_safe: bool,
    allow_careful: bool,
    max_steps: int,
) -> AutonomousPlan:
    """Filter an autonomous plan against the local registry and approval policy."""
    seen: set[str] = set()
    sanitized_steps: list[AutonomousStep] = []
    for step in plan.steps:
        if step.tool_name in seen:
            continue
        try:
            tool = registry.get(step.tool_name)
        except KeyError:
            continue
        if tool.category.value == "active_safe" and not auto_safe:
            continue
        if tool.category.value == "active_careful" and not allow_careful:
            continue
        seen.add(step.tool_name)
        sanitized_steps.append(step)
        if len(sanitized_steps) >= max_steps:
            break

    report_formats = [fmt for fmt in plan.report_formats if fmt in {"markdown", "html", "json"}]
    if not report_formats:
        report_formats = ["markdown", "html", "json"]
    return AutonomousPlan(
        strategy=plan.strategy,
        steps=sanitized_steps,
        report_formats=report_formats,
    )
