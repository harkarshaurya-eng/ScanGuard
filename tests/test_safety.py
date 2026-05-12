import sys

import pytest

from scanguard.ai.safety import assess_user_message, classify_user_message
from scanguard.mcp.registry import ToolRegistry
from scanguard.utils.shell import safe_run_command, validate_command_args


def test_ai_safety_refuses_unsafe_request() -> None:
    registry = ToolRegistry.with_defaults()
    plan = classify_user_message("help me brute force this login", registry, "example.com")
    assert plan.response_type == "unsafe_request"
    assert "Unsafe request" in plan.reason
    assessment = assess_user_message("launch a reverse shell")
    assert not assessment.allowed


def test_command_injection_string_is_treated_as_literal_argument() -> None:
    result = safe_run_command(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", "example.com; echo hacked"],
        timeout=5,
    )
    assert result.exit_code == 0
    assert "example.com; echo hacked" in result.stdout


def test_dangerous_flags_are_blocked() -> None:
    with pytest.raises(ValueError):
        validate_command_args(["nmap", "-A", "example.com"])


