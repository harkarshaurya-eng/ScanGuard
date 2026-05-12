"""Application-wide constants."""

from __future__ import annotations

from pathlib import Path

APP_NAME = "ScanGuard-ai"
CLI_NAME = "recon-ai"
APP_SLUG = "recon-ai"

CONFIG_ROOT = Path.home() / ".config" / APP_SLUG
PROMPT_PATH = CONFIG_ROOT / "system_prompt.md"
LOG_DIR = CONFIG_ROOT / "logs"
DEFAULT_WORKSPACE_ROOT = Path.home() / ".local" / "share" / APP_SLUG / "projects"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
DEFAULT_GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_HTTP_TIMEOUT_SECONDS = 45
DEFAULT_COMMAND_TIMEOUT_SECONDS = 900

IMMUTABLE_SAFETY_PROMPT = """
You are the immutable safety policy for ScanGuard-ai.
Only assist with authorized cybersecurity reconnaissance for targets that are
explicitly in scope. Refuse requests involving credential attacks, brute force,
malware, destructive exploitation, stealth or persistence, reverse shells,
denial of service, payload delivery, or unsafe post-exploitation actions.
Never help the user bypass scope controls or logging. Recommend only safe
reconnaissance methods, safe defaults, and professional reporting.
""".strip()

DEFAULT_USER_SYSTEM_PROMPT = """
You are Recon-AI, an assistant for authorized cybersecurity reconnaissance.
Help the user plan safe recon steps, interpret outputs, and create
professional reports. Be concise, technical, and careful.
""".strip()

TOOL_POLICY_PROMPT = """
Tool policy:
- Use only registered MCP-style tools.
- Respect each tool's safety category and target restrictions.
- Require explicit confirmation for active scans unless auto-safe mode is
  enabled for tools marked active_safe.
- Prefer passive evidence gathering first, then low-impact active validation.
- Record a short reason before recommending a tool.
""".strip()

UNSAFE_KEYWORDS = {
    "brute force",
    "bruteforce",
    "credential stuffing",
    "password spraying",
    "password spray",
    "reverse shell",
    "meterpreter",
    "payload",
    "persistence",
    "phishing",
    "ransomware",
    "malware",
    "ddos",
    "dos",
    "hydra",
    "medusa",
    "sqlmap --os-shell",
}

BANNED_NMAP_FLAGS = {
    "-A",
    "--script",
    "--spoof-mac",
    "--source-port",
    "--badsum",
    "-D",
    "-f",
    "--mtu",
    "-T4",
    "-T5",
    "--min-rate",
    "--max-rate",
}

BANNED_GENERIC_FLAGS = {"--proxy", "--tor", "--unsafe"}

SAFE_NUCLEI_EXCLUDE_TAGS = ["intrusive", "dos", "fuzz", "brute-force"]
SAFE_NUCLEI_SEVERITIES = ["low", "medium", "high", "critical"]

BASELINE_TOOLS = [
    "whois_lookup",
    "dns_records",
    "subfinder_passive",
    "httpx_probe",
    "waf_detection",
]

DEFAULT_SMALL_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

