"""Parser for naabu port scan output."""

from __future__ import annotations

from scanguard.parsers.generic_parser import parse_json_lines
from scanguard.parsers.nmap_parser import RISKY_PORTS
from scanguard.storage.models import ParsedAsset, ParsedFinding, ParsedToolOutput


def parse_naabu_output(stdout: str, target: str) -> ParsedToolOutput:
    """Parse naabu JSON lines or fallback host:port output."""
    rows = parse_json_lines(stdout)
    ports: list[int] = []
    observations: list[str] = []

    if rows:
        for row in rows:
            port = int(row.get("port", 0) or 0)
            if port > 0:
                ports.append(port)
                host = str(row.get("host") or row.get("ip") or target)
                observations.append(f"{host}:{port}")
    else:
        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped or ":" not in stripped:
                continue
            host, port_text = stripped.rsplit(":", 1)
            if not port_text.isdigit():
                continue
            ports.append(int(port_text))
            observations.append(f"{host}:{port_text}")

    assets = [
        ParsedAsset(
            asset_type="open_port",
            value=str(port),
            metadata={"target": target, "port": port},
        )
        for port in ports
    ]
    findings: list[ParsedFinding] = []
    for port in ports:
        if port in RISKY_PORTS:
            title, recommendation = RISKY_PORTS[port]
            findings.append(
                ParsedFinding(
                    title=title,
                    severity="medium",
                    confidence="medium",
                    evidence=f"Open TCP port {port}",
                    affected_asset=target,
                    source_tool="naabu_top_ports",
                    recommendation=recommendation,
                )
            )

    return ParsedToolOutput(
        summary=f"Naabu identified {len(ports)} open ports on {target}.",
        assets=assets,
        findings=findings,
        raw_observations=observations,
        metadata={"target": target, "port_count": len(ports)},
    )

