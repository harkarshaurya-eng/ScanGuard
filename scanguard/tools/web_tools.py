"""Web reconnaissance tool wrappers."""

from __future__ import annotations

from pathlib import Path

from scanguard.constants import DEFAULT_SMALL_WORDLIST, SAFE_NUCLEI_EXCLUDE_TAGS, SAFE_NUCLEI_SEVERITIES
from scanguard.mcp.schemas import TargetType, ToolCategory, ToolDefinition, ToolExecutionInput
from scanguard.parsers.generic_parser import detect_interesting_paths, parse_lines_as_assets
from scanguard.parsers.headers_parser import parse_http_headers_output
from scanguard.parsers.httpx_parser import parse_httpx_output
from scanguard.parsers.nikto_parser import parse_nikto_output
from scanguard.parsers.nuclei_parser import parse_nuclei_output
from scanguard.storage.models import ParsedFinding, ParsedToolOutput
from scanguard.tools.base import as_url, no_extra_args, resolve_binary_candidate


def _httpx_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    binary = resolve_binary_candidate(
        "httpx",
        env_var="SCANGUARD_HTTPX_BINARY",
        validator_name="projectdiscovery_httpx",
    )
    return [
        binary,
        "-u",
        as_url(input_data.target),
        "-json",
        "-title",
        "-tech-detect",
        "-web-server",
        "-status-code",
        "-follow-host-redirects",
    ]


def _wafw00f_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["wafw00f", as_url(input_data.target)]


def _curl_headers_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return [
        "curl",
        "-sS",
        "-I",
        "-L",
        "--max-redirs",
        "3",
        "--connect-timeout",
        "10",
        as_url(input_data.target),
    ]


def _whatweb_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["whatweb", "--no-errors", "--log-brief=-", as_url(input_data.target)]


def _nikto_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    return ["nikto", "-h", as_url(input_data.target), "-ask", "no", "-nointeractive"]


def _nuclei_command(input_data: ToolExecutionInput) -> list[str]:
    no_extra_args(input_data)
    severities = ",".join(input_data.severity_filter or SAFE_NUCLEI_SEVERITIES)
    excluded = ",".join(SAFE_NUCLEI_EXCLUDE_TAGS)
    return [
        "nuclei",
        "-u",
        as_url(input_data.target),
        "-jsonl",
        "-severity",
        severities,
        "-exclude-tags",
        excluded,
    ]


def _gobuster_command(input_data: ToolExecutionInput) -> list[str]:
    wordlist = input_data.wordlist or DEFAULT_SMALL_WORDLIST
    if not Path(wordlist).exists():
        raise ValueError(f"Wordlist not found: {wordlist}")
    return [
        "gobuster",
        "dir",
        "-u",
        as_url(input_data.target),
        "-w",
        wordlist,
        "-q",
        "-t",
        "5",
        "--timeout",
        "10s",
    ]


def _ffuf_command(input_data: ToolExecutionInput) -> list[str]:
    wordlist = input_data.wordlist or DEFAULT_SMALL_WORDLIST
    if not Path(wordlist).exists():
        raise ValueError(f"Wordlist not found: {wordlist}")
    return [
        "ffuf",
        "-u",
        f"{as_url(input_data.target).rstrip('/')}/FUZZ",
        "-w",
        wordlist,
        "-t",
        "5",
        "-rate",
        "25",
        "-fc",
        "404",
        "-s",
    ]


def _waf_parser(stdout: str, target: str) -> ParsedToolOutput:
    parsed = parse_lines_as_assets(stdout, target, "waf_line", "waf_detection")
    findings = list(parsed.findings)
    if "is behind" in stdout.lower():
        findings.append(
            ParsedFinding(
                title="WAF detected",
                severity="info",
                confidence="high",
                evidence=stdout.strip(),
                affected_asset=target,
                source_tool="waf_detection",
                recommendation="Record the WAF presence when planning any follow-up validation.",
            )
        )
    return ParsedToolOutput(
        summary=parsed.summary,
        assets=parsed.assets,
        findings=findings,
        raw_observations=parsed.raw_observations,
        metadata=parsed.metadata,
    )


def _whatweb_parser(stdout: str, target: str) -> ParsedToolOutput:
    parsed = parse_lines_as_assets(stdout, target, "web_fingerprint", "whatweb_fingerprint")
    return ParsedToolOutput(
        summary=parsed.summary,
        assets=parsed.assets,
        findings=detect_interesting_paths(stdout, target, "whatweb_fingerprint"),
        raw_observations=parsed.raw_observations,
        metadata=parsed.metadata,
    )


def _dir_parser(stdout: str, target: str, source_tool: str) -> ParsedToolOutput:
    parsed = parse_lines_as_assets(stdout, target, "web_path", source_tool)
    return ParsedToolOutput(
        summary=parsed.summary,
        assets=parsed.assets,
        findings=detect_interesting_paths(stdout, target, source_tool),
        raw_observations=parsed.raw_observations,
        metadata=parsed.metadata,
    )


def build_web_tools() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="httpx_probe",
            description="Probe an HTTP endpoint and fingerprint technologies.",
            category=ToolCategory.active_safe,
            binary="httpx",
            input_schema={"target": "url|domain"},
            requires_confirmation=True,
            command_builder=_httpx_command,
            parser=parse_httpx_output,
            timeout_seconds=180,
            rate_limit_seconds=20,
            allowed_target_types=[TargetType.domain, TargetType.url],
        ),
        ToolDefinition(
            name="waf_detection",
            description="Detect common web application firewalls.",
            category=ToolCategory.active_safe,
            binary="wafw00f",
            input_schema={"target": "url|domain"},
            requires_confirmation=True,
            command_builder=_wafw00f_command,
            parser=_waf_parser,
            timeout_seconds=120,
            rate_limit_seconds=20,
            allowed_target_types=[TargetType.domain, TargetType.url],
        ),
        ToolDefinition(
            name="curl_headers",
            description="Collect HTTP response headers and identify missing hardening headers.",
            category=ToolCategory.active_safe,
            binary="curl",
            input_schema={"target": "url|domain"},
            requires_confirmation=True,
            command_builder=_curl_headers_command,
            parser=parse_http_headers_output,
            timeout_seconds=120,
            rate_limit_seconds=15,
            allowed_target_types=[TargetType.domain, TargetType.url],
        ),
        ToolDefinition(
            name="whatweb_fingerprint",
            description="Fingerprint technologies used by a web application.",
            category=ToolCategory.active_safe,
            binary="whatweb",
            input_schema={"target": "url|domain"},
            requires_confirmation=True,
            command_builder=_whatweb_command,
            parser=_whatweb_parser,
            timeout_seconds=180,
            rate_limit_seconds=20,
            allowed_target_types=[TargetType.domain, TargetType.url],
        ),
        ToolDefinition(
            name="nikto_basic",
            description="Run Nikto with conservative defaults.",
            category=ToolCategory.active_careful,
            binary="nikto",
            input_schema={"target": "url|domain"},
            requires_confirmation=True,
            command_builder=_nikto_command,
            parser=parse_nikto_output,
            timeout_seconds=600,
            rate_limit_seconds=60,
            allowed_target_types=[TargetType.domain, TargetType.url],
        ),
        ToolDefinition(
            name="nuclei_safe",
            description="Run nuclei with safe severity filters and excluded intrusive tags.",
            category=ToolCategory.active_careful,
            binary="nuclei",
            input_schema={"target": "url|domain"},
            requires_confirmation=True,
            command_builder=_nuclei_command,
            parser=parse_nuclei_output,
            timeout_seconds=600,
            rate_limit_seconds=60,
            allowed_target_types=[TargetType.domain, TargetType.url],
        ),
        ToolDefinition(
            name="gobuster_dirs",
            description="Perform low-rate directory discovery with Gobuster.",
            category=ToolCategory.active_careful,
            binary="gobuster",
            input_schema={"target": "url|domain", "wordlist": "optional"},
            requires_confirmation=True,
            command_builder=_gobuster_command,
            parser=lambda stdout, target: _dir_parser(stdout, target, "gobuster_dirs"),
            timeout_seconds=600,
            rate_limit_seconds=90,
            allowed_target_types=[TargetType.domain, TargetType.url],
        ),
        ToolDefinition(
            name="ffuf_dirs",
            description="Perform low-rate directory discovery with ffuf.",
            category=ToolCategory.active_careful,
            binary="ffuf",
            input_schema={"target": "url|domain", "wordlist": "optional"},
            requires_confirmation=True,
            command_builder=_ffuf_command,
            parser=lambda stdout, target: _dir_parser(stdout, target, "ffuf_dirs"),
            timeout_seconds=600,
            rate_limit_seconds=90,
            allowed_target_types=[TargetType.domain, TargetType.url],
        ),
    ]


