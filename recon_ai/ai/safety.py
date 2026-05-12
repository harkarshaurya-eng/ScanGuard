"""Safety filters and intent classification."""

from __future__ import annotations

import re
from dataclasses import dataclass

from recon_ai.constants import UNSAFE_KEYWORDS
from recon_ai.mcp.registry import ToolRegistry
from recon_ai.mcp.schemas import ToolPlan


@dataclass(slots=True)
class SafetyAssessment:
    allowed: bool
    response_type: str
    refusal_message: str | None = None


def assess_user_message(message: str) -> SafetyAssessment:
    """Refuse obviously unsafe requests before model involvement."""
    lowered = message.lower()
    for keyword in UNSAFE_KEYWORDS:
        if keyword in lowered:
            return SafetyAssessment(
                allowed=False,
                response_type="unsafe_request",
                refusal_message=(
                    "I can't help with credential attacks, exploitation, persistence, or other unsafe actions. "
                    "I can help with scoped reconnaissance, findings review, safe enumeration, and reporting."
                ),
            )
    return SafetyAssessment(allowed=True, response_type="allowed")


def classify_user_message(message: str, registry: ToolRegistry, target: str) -> ToolPlan:
    """Classify user intent into a structured response type."""
    safety = assess_user_message(message)
    if not safety.allowed:
        return ToolPlan(
            intent="refuse",
            reason="Unsafe request detected.",
            response_type="unsafe_request",
            answer=safety.refusal_message,
            target=target,
        )

    lowered = message.lower().strip()
    if lowered.startswith("generate a report") or "/report" in lowered or lowered.startswith("report"):
        return ToolPlan(
            intent="generate_report",
            reason="The user asked for a report.",
            response_type="generate_report",
            target=target,
        )
    if lowered.startswith("explain") or "/explain" in lowered:
        return ToolPlan(
            intent="explain_finding",
            reason="The user asked to explain a finding.",
            response_type="explain_finding",
            target=target,
        )
    suggested_tool = infer_tool_from_message(lowered, registry)
    if suggested_tool:
        response_type = "run_tool_request" if lowered.startswith("run ") or " run " in f" {lowered} " else "propose_tool"
        tool = registry.get(suggested_tool)
        return ToolPlan(
            intent="run_tool" if response_type == "run_tool_request" else "propose_tool",
            tool_name=suggested_tool,
            reason=f"Recommended tool for this request: {tool.description}",
            target=target,
            requires_confirmation=tool.requires_confirmation,
            risk_level=tool.category.value,
            response_type=response_type,
        )
    return ToolPlan(
        intent="answer",
        reason="The user asked a question or requested guidance.",
        target=target,
        response_type="answer_question",
    )


def infer_tool_from_message(message: str, registry: ToolRegistry) -> str | None:
    """Infer a registered tool name from natural language."""
    keyword_map = {
        "dns": "dns_records",
        "nslookup": "nslookup_query",
        "host": "host_lookup",
        "subdomain": "subfinder_passive",
        "amass": "amass_passive",
        "whois": "whois_lookup",
        "httpx": "httpx_probe",
        "waf": "waf_detection",
        "whatweb": "whatweb_fingerprint",
        "nikto": "nikto_basic",
        "nuclei": "nuclei_safe",
        "nmap": "nmap_basic",
        "ports": "nmap_basic",
        "tls": "sslscan_basic",
        "ssl": "sslscan_basic",
        "gobuster": "gobuster_dirs",
        "ffuf": "ffuf_dirs",
        "directory": "gobuster_dirs",
        "metadata": "theharvester_passive",
        "harvester": "theharvester_passive",
    }
    for keyword, tool_name in keyword_map.items():
        if re.search(rf"\b{re.escape(keyword)}\b", message):
            if any(tool.name == tool_name for tool in registry.list()):
                return tool_name
    if message in {tool.name for tool in registry.list()}:
        return message
    return None

