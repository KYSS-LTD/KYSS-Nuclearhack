"""Analyzers for regex and entropy-based secret detection."""

from __future__ import annotations

import math
import re

from .guidance import enrich_with_guidance
from .models import Finding
from .patterns import PATTERNS, SecretPattern


TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
CONTEXT_RE = re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|key|credential)\b")
COMMON_TEST_VALUES = {"example", "sample", "test", "dummy", "placeholder", "changeme"}
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
TOKEN_PREFIX_RE = re.compile(r"^(?:AKIA|gh[pousr]_?|xox[baprs]-|AIza|sk_live_|rk_live_)")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_likely_test_data(line: str, token: str) -> bool:
    lowered_line = line.lower()
    lowered_token = token.lower()
    if any(word in lowered_line or word in lowered_token for word in COMMON_TEST_VALUES):
        return True
    return False


def _entropy_severity(line: str) -> str:
    return "high" if CONTEXT_RE.search(line) else "medium"


def _entropy_score(token: str) -> int:
    score = 0
    if len(token) >= 32:
        score += 2
    elif len(token) >= 24:
        score += 1
    if BASE64_RE.match(token):
        score += 1
    if HEX_RE.match(token) and len(token) >= 32:
        score += 1
    if TOKEN_PREFIX_RE.match(token):
        score += 2
    return score


def analyze_line(
    file_path: str,
    line_number: int,
    line: str,
    entropy_threshold: float,
    extra_patterns: tuple[SecretPattern, ...] = (),
) -> list[Finding]:
    findings: list[Finding] = []

    for secret_pattern in (*PATTERNS, *extra_patterns):
        match = secret_pattern.pattern.search(line)
        if match:
            findings.append(
                enrich_with_guidance(Finding(
                    file_path=file_path,
                    line_number=line_number,
                    detector="regex",
                    secret_type=secret_pattern.name,
                    severity=secret_pattern.severity,
                    snippet=line.strip()[:240],
                    entropy=None,
                ))
            )

    for candidate in TOKEN_RE.findall(line):
        if len(candidate) < 24 or _is_likely_test_data(line, candidate):
            continue
        entropy = shannon_entropy(candidate)
        if entropy >= entropy_threshold:
            severity = _entropy_severity(line)
            if _entropy_score(candidate) >= 3 and severity == "medium":
                severity = "high"
            findings.append(
                enrich_with_guidance(Finding(
                    file_path=file_path,
                    line_number=line_number,
                    detector="entropy",
                    secret_type="unknown_high_entropy",
                    severity=severity,
                    snippet=line.strip()[:240],
                    entropy=round(entropy, 3),
                ))
            )

    return findings
