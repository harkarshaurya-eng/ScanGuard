"""Parser for nuclei JSONL output."""

from __future__ import annotations

from scanguard.parsers.generic_parser import parse_json_lines
from scanguard.storage.models import ParsedAsset, ParsedFinding, ParsedToolOutput


def parse_nuclei_output(stdout: str, target: str) -> ParsedToolOutput:
    """Parse nuclei JSONL findings."""
    rows = parse_json_lines(stdout)
    findings: list[ParsedFinding] = []
    assets: list[ParsedAsset] = []
    observations: list[str] = []

    for row in rows:
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        severity = str(info.get("severity", "info")).lower()
        name = str(info.get("name", "Nuclei finding"))
        matched = str(row.get("matched-at", target))
        template_id = str(row.get("template-id", "unknown"))
        description = str(info.get("description", "")).strip()
        evidence = f"{matched} [{template_id}] {description}".strip()
        findings.append(
            ParsedFinding(
                title=name,
                severity=severity if severity in {"info", "low", "medium", "high", "critical"} else "info",
                confidence="medium",
                evidence=evidence,
                affected_asset=matched,
                source_tool="nuclei_safe",
                recommendation="Validate the template result manually and remediate the exposed condition if confirmed.",
            )
        )
        observations.append(evidence)
        assets.append(
            ParsedAsset(
                asset_type="nuclei_match",
                value=matched,
                metadata={"template_id": template_id, "severity": severity},
            )
        )

    return ParsedToolOutput(
        summary=f"Parsed {len(findings)} nuclei findings.",
        assets=assets,
        findings=findings,
        raw_observations=observations,
        metadata={"target": target},
    )


