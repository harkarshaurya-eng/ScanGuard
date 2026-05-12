"""Parsers for nmap XML output."""

from __future__ import annotations

from xml.etree import ElementTree

from scanguard.storage.models import ParsedAsset, ParsedFinding, ParsedToolOutput


RISKY_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP service exposed", "Review whether FTP is required and disable or restrict it."),
    23: ("Telnet service exposed", "Disable Telnet and migrate to SSH."),
    2375: ("Unauthenticated Docker API exposed", "Restrict Docker API access and require TLS."),
    3389: ("RDP service exposed", "Ensure RDP is necessary, restricted, and protected."),
    5900: ("VNC service exposed", "Restrict VNC exposure and enforce strong authentication."),
}


def parse_nmap_xml(stdout: str, target: str) -> ParsedToolOutput:
    """Parse nmap XML emitted to stdout."""
    try:
        root = ElementTree.fromstring(stdout)
    except ElementTree.ParseError:
        return ParsedToolOutput(summary="Nmap output was not valid XML.", metadata={"target": target})

    assets: list[ParsedAsset] = []
    findings: list[ParsedFinding] = []
    observations: list[str] = []

    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            port_id = int(port.attrib.get("portid", "0"))
            protocol = port.attrib.get("protocol", "tcp")
            service = port.find("service")
            service_name = service.attrib.get("name", "unknown") if service is not None else "unknown"
            product = service.attrib.get("product", "") if service is not None else ""
            version = service.attrib.get("version", "") if service is not None else ""
            descriptor = f"{protocol}/{port_id} {service_name} {product} {version}".strip()
            observations.append(descriptor)
            assets.append(
                ParsedAsset(
                    asset_type="service",
                    value=descriptor,
                    metadata={"port": port_id, "protocol": protocol, "service": service_name},
                )
            )
            if port_id in RISKY_PORTS:
                title, recommendation = RISKY_PORTS[port_id]
                findings.append(
                    ParsedFinding(
                        title=title,
                        severity="medium",
                        confidence="high",
                        evidence=descriptor,
                        affected_asset=target,
                        source_tool="nmap_basic",
                        recommendation=recommendation,
                    )
                )

    return ParsedToolOutput(
        summary=f"Discovered {len(observations)} open services on {target}.",
        assets=assets,
        findings=findings,
        raw_observations=observations,
        metadata={"target": target},
    )


