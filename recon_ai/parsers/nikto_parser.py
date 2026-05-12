"""Parser for Nikto text output."""

from __future__ import annotations

from recon_ai.storage.models import ParsedFinding, ParsedToolOutput


KEYWORD_FINDINGS = {
    "directory indexing": ("Directory listing exposed", "Disable directory indexing where it is not required."),
    ".git": ("Potential exposed .git content", "Remove public access to VCS metadata and rotate any exposed secrets."),
    "admin": ("Administrative path referenced", "Review whether the administrative interface should be internet-accessible."),
    "outdated": ("Potential outdated software indicator", "Confirm software versions and update unsupported components."),
}


def parse_nikto_output(stdout: str, target: str) -> ParsedToolOutput:
    """Parse Nikto text output into lightweight findings."""
    findings: list[ParsedFinding] = []
    observations: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("- Nikto"):
            continue
        observations.append(stripped)
        lowered = stripped.lower()
        for keyword, (title, recommendation) in KEYWORD_FINDINGS.items():
            if keyword in lowered:
                findings.append(
                    ParsedFinding(
                        title=title,
                        severity="medium",
                        confidence="medium",
                        evidence=stripped,
                        affected_asset=target,
                        source_tool="nikto_basic",
                        recommendation=recommendation,
                    )
                )
    return ParsedToolOutput(
        summary=f"Nikto produced {len(observations)} notable output lines.",
        findings=findings,
        raw_observations=observations,
        metadata={"target": target},
    )

