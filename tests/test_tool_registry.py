import pytest

from scanguard.mcp.registry import ToolRegistry


def test_tool_registry_contains_expected_tools() -> None:
    registry = ToolRegistry.with_defaults()
    tools = registry.list()
    names = {tool.name for tool in tools}
    assert "nmap_basic" in names
    assert "httpx_probe" in names
    assert "whois_lookup" in names
    assert "curl_headers" in names
    assert "dnsrecon_standard" in names
    assert "assetfinder_passive" in names
    assert "naabu_top_ports" in names
    assert len(names) == len(tools)
    assert registry.get("httpx_probe").requires_confirmation is True


def test_registry_rejects_duplicate_registration() -> None:
    registry = ToolRegistry.with_defaults()
    tool = registry.get("nmap_basic")
    with pytest.raises(ValueError):
        registry.register(tool)


