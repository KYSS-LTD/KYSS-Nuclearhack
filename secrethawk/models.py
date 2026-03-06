"""Data models for findings and scan reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass(slots=True)
class Finding:
    file_path: str
    line_number: int
    detector: str
    secret_type: str
    severity: str
    snippet: str
    explanation: str = ""
    remediation: list[str] | None = None
    entropy: float | None = None

    def __post_init__(self) -> None:
        if self.remediation is None:
            self.remediation = []

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class ScanReport:
    repository: str
    scanned_at: str
    findings: list[Finding]

    @classmethod
    def create(cls, repository: str, findings: list[Finding]) -> "ScanReport":
        return cls(
            repository=repository,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            findings=findings,
        )

    def by_severity(self) -> dict[str, int]:
        counters = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            counters[finding.severity] = counters.get(finding.severity, 0) + 1
        return counters

    def to_dict(self) -> dict:
        return {
            "repository": self.repository,
            "scanned_at": self.scanned_at,
            "summary": self.by_severity(),
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
