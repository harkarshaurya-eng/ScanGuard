"""Registry for local tool definitions."""

from __future__ import annotations

from scanguard.mcp.schemas import ToolDefinition
from scanguard.tools.dns_tools import build_dns_tools
from scanguard.tools.metadata_tools import build_metadata_tools
from scanguard.tools.passive_tools import build_passive_tools
from scanguard.tools.port_tools import build_port_tools
from scanguard.tools.subdomain_tools import build_subdomain_tools
from scanguard.tools.tls_tools import build_tls_tools
from scanguard.tools.web_tools import build_web_tools


class ToolRegistry:
    """In-memory registry of safe tool definitions."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> None:
        if definition.name in self._tools:
            raise ValueError(f"Tool already registered: {definition.name}")
        self._tools[definition.name] = definition

    def get(self, name: str) -> ToolDefinition:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"Unknown tool: {name}") from exc

    def list(self) -> list[ToolDefinition]:
        return sorted(self._tools.values(), key=lambda tool: tool.name)

    @classmethod
    def with_defaults(cls) -> "ToolRegistry":
        registry = cls()
        builders = (
            build_passive_tools()
            + build_dns_tools()
            + build_subdomain_tools()
            + build_web_tools()
            + build_port_tools()
            + build_tls_tools()
            + build_metadata_tools()
        )
        for definition in builders:
            registry.register(definition)
        return registry


