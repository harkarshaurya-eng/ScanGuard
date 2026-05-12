"""TLS assessment wrappers."""

from __future__ import annotations

from scanguard.mcp.schemas import TargetType, ToolCategory, ToolDefinition, ToolExecutionInput
from scanguard.storage.models import ParsedAsset, ParsedFinding, ParsedToolOutput
from scanguard.tools.base import no_extra_args


def _sslscan_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["sslscan", input_data.target]


def _sslscan_parser(stdout: str, target: str) -> ParsedToolOutput:
    findings: list[ParsedFinding] = []
    assets: list[ParsedAsset] = []
    observations: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        observations.append(stripped)
        if "TLSv1.0" in stripped or "TLSv1.1" in stripped:
            findings.append(
                ParsedFinding(
                    title="Legacy TLS protocol supported",
                    severity="medium",
                    confidence="high",
                    evidence=stripped,
                    affected_asset=target,
                    source_tool="sslscan_basic",
                    recommendation="Disable TLS 1.0/1.1 support and require modern TLS versions.",
                )
            )
        if "Preferred TLSv1.3" in stripped or "Preferred TLSv1.2" in stripped:
            assets.append(ParsedAsset(asset_type="tls_profile", value=stripped, metadata={"target": target}))
    return ParsedToolOutput(
        summary=f"Collected {len(observations)} TLS observations.",
        assets=assets,
        findings=findings,
        raw_observations=observations,
        metadata={"target": target},
    )


def build_tls_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="sslscan_basic",
            description="Check TLS protocol and cipher exposure with sslscan.",
            category=ToolCategory.active_safe,
            binary="sslscan",
            input_schema={"target": "domain|ip"},
            requires_confirmation=True,
            command_builder=_sslscan_command,
            parser=_sslscan_parser,
            timeout_seconds=300,
            rate_limit_seconds=45,
            allowed_target_types=[TargetType.domain, TargetType.ip],
        )
    ]


