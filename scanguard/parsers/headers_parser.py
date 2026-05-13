"""Parser for HTTP response headers."""

from __future__ import annotations

from scanguard.storage.models import ParsedAsset, ParsedFinding, ParsedToolOutput

RECOMMENDED_SECURITY_HEADERS = {
    "content-security-policy": "Add a Content-Security-Policy header to reduce XSS and content injection risk.",
    "x-frame-options": "Add X-Frame-Options or an equivalent CSP frame-ancestors policy to reduce clickjacking risk.",
    "x-content-type-options": "Add X-Content-Type-Options: nosniff to reduce MIME confusion risk.",
    "referrer-policy": "Add a Referrer-Policy header to reduce unneeded leakage of sensitive URLs.",
    "strict-transport-security": "Enable HSTS on HTTPS services to enforce secure transport for repeat visitors.",
}

DISCLOSURE_HEADERS = {
    "server": "Review whether the Server header reveals unnecessary product information.",
    "x-powered-by": "Remove or minimize X-Powered-By disclosure to reduce low-effort fingerprinting.",
}


def parse_http_headers_output(stdout: str, target: str) -> ParsedToolOutput:
    """Parse curl header output and flag missing hardening headers."""
    header_block = _extract_final_header_block(stdout)
    header_map: dict[str, str] = {}
    assets: list[ParsedAsset] = []
    findings: list[ParsedFinding] = []

    for line in header_block:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        normalized_name = name.strip().lower()
        normalized_value = value.strip()
        header_map[normalized_name] = normalized_value
        assets.append(
            ParsedAsset(
                asset_type="http_header",
                value=f"{normalized_name}: {normalized_value}",
                metadata={"header_name": normalized_name, "target": target},
            )
        )

    missing_headers = [name for name in RECOMMENDED_SECURITY_HEADERS if name not in header_map]
    if missing_headers:
        findings.append(
            ParsedFinding(
                title="Missing recommended security headers",
                severity="low",
                confidence="high",
                evidence=", ".join(missing_headers),
                affected_asset=target,
                source_tool="curl_headers",
                recommendation=" ".join(RECOMMENDED_SECURITY_HEADERS[name] for name in missing_headers),
            )
        )

    for header_name, recommendation in DISCLOSURE_HEADERS.items():
        if header_name in header_map:
            findings.append(
                ParsedFinding(
                    title="Technology disclosure header present",
                    severity="info",
                    confidence="high",
                    evidence=f"{header_name}: {header_map[header_name]}",
                    affected_asset=target,
                    source_tool="curl_headers",
                    recommendation=recommendation,
                )
            )

    return ParsedToolOutput(
        summary=f"Parsed {len(header_map)} response headers from {target}.",
        assets=assets,
        findings=findings,
        raw_observations=header_block,
        metadata={"target": target, "header_count": len(header_map)},
    )


def _extract_final_header_block(stdout: str) -> list[str]:
    blocks: list[list[str]] = []
    current: list[str] = []
    in_headers = False

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            if current:
                blocks.append(current)
                current = []
            in_headers = False
            continue
        if line.startswith("HTTP/"):
            if current:
                blocks.append(current)
                current = []
            in_headers = True
            continue
        if in_headers:
            current.append(line)

    if current:
        blocks.append(current)
    return blocks[-1] if blocks else [line.strip() for line in stdout.splitlines() if line.strip()]

