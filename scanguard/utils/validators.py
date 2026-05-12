"""Target and scope validation helpers."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")


def normalize_domain(value: str) -> str:
    """Normalize a domain or wildcard domain."""
    candidate = value.strip().lower().rstrip(".")
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or ""
    if not candidate:
        raise ValueError("Domain is empty after normalization.")
    if "/" in candidate or "\\" in candidate:
        raise ValueError("Domain must not include path separators.")
    if candidate.startswith("*."):
        base = candidate[2:]
        if not DOMAIN_PATTERN.fullmatch(base):
            raise ValueError(f"Invalid wildcard domain: {value}")
        return f"*.{base}"
    if not DOMAIN_PATTERN.fullmatch(candidate):
        raise ValueError(f"Invalid domain: {value}")
    return candidate


def normalize_target(value: str) -> str:
    """Normalize a URL, hostname, or IP address to a comparable target."""
    stripped = value.strip()
    if not stripped:
        raise ValueError("Target cannot be empty.")
    parsed = urlparse(stripped if "://" in stripped else f"https://{stripped}")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Targets must not include paths, query strings, or fragments.")
    host = parsed.hostname or stripped
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return normalize_domain(host)


@dataclass(frozen=True)
class ScopeRule:
    raw: str
    normalized: str
    kind: str


class ScopeAuthorizer:
    """Validates whether targets are inside a scope file."""

    def __init__(self, rules: list[ScopeRule]) -> None:
        self.rules = rules

    @classmethod
    def from_file(cls, path: Path) -> "ScopeAuthorizer":
        rules: list[ScopeRule] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            rules.append(parse_scope_rule(stripped))
        if not rules:
            raise ValueError("Scope file does not contain any valid scope rules.")
        return cls(rules)

    def is_authorized(self, target: str) -> bool:
        normalized = normalize_target(target)
        for rule in self.rules:
            if rule.kind == "domain" and normalized == rule.normalized:
                return True
            if rule.kind == "wildcard" and _matches_wildcard(normalized, rule.normalized):
                return True
            if rule.kind == "cidr" and _matches_cidr(normalized, rule.normalized):
                return True
        return False

    def explain(self) -> list[str]:
        return [rule.normalized for rule in self.rules]


def parse_scope_rule(value: str) -> ScopeRule:
    stripped = value.strip()
    if stripped.startswith("*."):
        return ScopeRule(raw=value, normalized=normalize_domain(stripped), kind="wildcard")
    try:
        network = ipaddress.ip_network(stripped, strict=False)
    except ValueError:
        return ScopeRule(raw=value, normalized=normalize_domain(stripped), kind="domain")
    return ScopeRule(raw=value, normalized=str(network), kind="cidr")


def _matches_wildcard(target: str, wildcard_rule: str) -> bool:
    suffix = wildcard_rule[2:]
    return target.endswith(f".{suffix}") and target != suffix


def _matches_cidr(target: str, cidr_rule: str) -> bool:
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return False
    return address in ipaddress.ip_network(cidr_rule, strict=False)
