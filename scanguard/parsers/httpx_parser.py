"""Parser for httpx JSONL output."""

from __future__ import annotations

from scanguard.parsers.generic_parser import parse_json_lines
from scanguard.storage.models import ParsedAsset, ParsedFinding, ParsedToolOutput


def parse_httpx_output(stdout: str, target: str) -> ParsedToolOutput:
    """Parse httpx-toolkit JSONL output."""
    rows = parse_json_lines(stdout)
    assets: list[ParsedAsset] = []
    findings: list[ParsedFinding] = []
    observations: list[str] = []

    for row in rows:
        url = str(row.get("url", target))
        status_code = int(row.get("status_code", 0) or 0)
        title = str(row.get("title", ""))
        tech = row.get("tech") or []
        webserver = str(row.get("webserver", ""))
        observations.append(f"{url} [{status_code}] {title}".strip())
        assets.append(
            ParsedAsset(
                asset_type="web_asset",
                value=url,
                metadata={"status_code": status_code, "title": title, "tech": tech, "webserver": webserver},
            )
        )
        lowered = f"{url} {title}".lower()
        if "admin" in lowered or "dashboard" in lowered:
            findings.append(
                ParsedFinding(
                    title="Potential admin interface discovered",
                    severity="medium",
                    confidence="medium",
                    evidence=f"{url} [{status_code}] {title}",
                    affected_asset=url,
                    source_tool="httpx_probe",
                    recommendation="Verify whether the interface should be publicly exposed and protect it with strong access controls.",
                )
            )
        if any(str(item).lower() in {"phpmyadmin", "wordpress", "jenkins"} for item in tech):
            findings.append(
                ParsedFinding(
                    title="Notable web technology detected",
                    severity="low",
                    confidence="medium",
                    evidence=f"{url} -> {', '.join(str(item) for item in tech)}",
                    affected_asset=url,
                    source_tool="httpx_probe",
                    recommendation="Review patch level, exposure, and hardening guidance for the detected technology.",
                )
            )

    return ParsedToolOutput(
        summary=f"Identified {len(assets)} reachable web assets via httpx.",
        assets=assets,
        findings=findings,
        raw_observations=observations,
        metadata={"target": target},
    )


