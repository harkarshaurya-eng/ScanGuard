from scanguard.ai.autopilot import build_offline_autonomous_plan
from scanguard.mcp.registry import ToolRegistry


def test_offline_autopilot_plan_respects_careful_flag() -> None:
    plan = build_offline_autonomous_plan(
        ToolRegistry.with_defaults(),
        auto_safe=True,
        allow_careful=False,
        max_steps=10,
    )
    tool_names = [step.tool_name for step in plan.steps]
    assert "whois_lookup" in tool_names
    assert "httpx_probe" in tool_names
    assert "nikto_basic" not in tool_names
    assert "nuclei_safe" not in tool_names


def test_offline_autopilot_plan_includes_careful_tools_when_allowed() -> None:
    plan = build_offline_autonomous_plan(
        ToolRegistry.with_defaults(),
        auto_safe=True,
        allow_careful=True,
        max_steps=12,
    )
    tool_names = [step.tool_name for step in plan.steps]
    assert "nikto_basic" in tool_names
    assert "nuclei_safe" in tool_names
