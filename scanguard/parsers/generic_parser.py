"""Generic parser helpers."""

from __future__ import annotations

import json
import re

from scanguard.storage.models import ParsedAsset, ParsedFinding, ParsedToolOutput


def parse_lines_as_assets(stdout: str, target: str, asset_type: str, source_tool: str) -> ParsedToolOutput:
    """Treat non-empty output lines as simple assets."""
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    assets = [
        ParsedAsset(asset_type=asset_type, value=line, metadata={"source_tool": source_tool})
        for line in lines
    ]
    return ParsedToolOutput(
        summary=f"Collected {len(assets)} {asset_type} observations from {source_tool}.",
        assets=assets,
        raw_observations=lines,
        metadata={"target": target, "source_tool": source_tool},
    )


def parse_json_lines(stdout: str) -> list[dict[str, object]]:
    """Parse JSONL and skip invalid rows."""
    rows: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def detect_interesting_paths(stdout: str, target: str, source_tool: str) -> list[ParsedFinding]:
    """Generate lightweight findings from common web paths."""
    findings: list[ParsedFinding] = []
    for match in re.finditer(r"(/(?:admin|login|dashboard|config|\.git|backup)[^\s]*)", stdout, re.IGNORECASE):
        findings.append(
            ParsedFinding(
                title="Interesting web path discovered",
                severity="medium",
                confidence="medium",
                evidence=match.group(1),
                affected_asset=target,
                source_tool=source_tool,
                recommendation="Review the endpoint for unnecessary exposure and access control.",
            )
        )
    return findings


