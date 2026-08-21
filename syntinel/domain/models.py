from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEVERITY_ORDER: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def severity_at_least(severity: str, floor: str) -> bool:
    """Return True if `severity` is at or above `floor` on the CRITICAL..LOW scale."""
    return _SEVERITY_ORDER.get(severity.upper(), -1) >= _SEVERITY_ORDER.get(floor.upper(), 0)


class FindingClass(StrEnum):
    """Vulnerability category assigned to a finding."""

    INJECTION = "injection"
    AUTH = "auth"
    SECRETS = "secrets"
    XSS = "xss"
    LOGIC = "logic"
    CONCURRENCY = "concurrency"
    UNHANDLED_EXCEPTION = "unhandled_exception"
    OTHER = "other"

    @classmethod
    def from_str(cls, value: str | None) -> "FindingClass":
        if not value:
            return cls.OTHER
        try:
            return cls(value.strip().lower())
        except ValueError:
            return cls.OTHER


@dataclass(slots=True)
class ReviewFinding:
    """A single security or correctness finding from an engine."""

    severity: Severity
    file_path: str
    issue: str
    line_number: int | None = None
    suggestion: str = ""
    title: str = ""
    finding_class: FindingClass = FindingClass.OTHER
    proof: str = ""
    source: Literal["llm", "semgrep", "llm+semgrep"] = "llm"


@dataclass(slots=True)
class SkippedFile:
    """A file that was excluded from the scan and why."""

    path: str
    reason: str


@dataclass(slots=True)
class ScanReport:
    """Aggregate result of a local `syntinel scan` run."""

    findings: list[ReviewFinding] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    files_scanned: int = 0
    duration_seconds: float = 0.0

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "CRITICAL" for f in self.findings)


@dataclass(slots=True)
class ReviewReport:
    """Aggregate result of a PR review (Cloud surface)."""

    findings: list[ReviewFinding] = field(default_factory=list)
    diff_trimmed: bool = False

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "CRITICAL" for f in self.findings)


@dataclass(slots=True)
class PullRequestEvent:
    """Normalized representation of a GitHub pull_request webhook payload."""

    action: str
    number: int
    repo_full_name: str
    head_sha: str
    title: str
    author: str
