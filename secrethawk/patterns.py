"""Known secret regex patterns and severity mapping."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    severity: str


PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        name="aws_access_key",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        severity="critical",
    ),
    SecretPattern(
        name="github_token",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        severity="high",
    ),
    SecretPattern(
        name="slack_token",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,200}\b"),
        severity="high",
    ),
    SecretPattern(
        name="stripe_api_key",
        pattern=re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        severity="critical",
    ),
    SecretPattern(
        name="google_api_key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        severity="high",
    ),
    SecretPattern(
        name="jwt_token",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        severity="high",
    ),
    SecretPattern(
        name="oauth_bearer",
        pattern=re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}"),
        severity="high",
    ),
    SecretPattern(
        name="private_key_header",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        severity="critical",
    ),
    SecretPattern(
        name="password_assignment",
        pattern=re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
        severity="high",
    ),
    SecretPattern(
        name="generic_api_key",
        pattern=re.compile(r"(?i)\b(api[_-]?key|token|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
        severity="high",
    ),
)

SEVERITY_ORDER = ("critical", "high", "medium", "low")
