import re

from syntinel.core.logging import get_logger
from syntinel.domain.models import FindingClass, ReviewFinding

logger = get_logger(__name__)

_NO_ISSUES_SENTINEL = "NO_ISSUES_FOUND"
_BINARY_MARKERS = ("Binary files", "GIT binary patch")
_VALID_SEVERITIES: frozenset[str] = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})

# A delimiter line is one that contains only dashes (>= 3), covering both the
# legacy "---" and the security prompt's "----".
_DELIMITER_RE = re.compile(r"^\s*-{3,}\s*$")
# Extract the first integer from a LINE value like "42", "42-58", or "unknown".
_FIRST_INT_RE = re.compile(r"\d+")


def _split_blocks(raw: str) -> list[str]:
    """Split raw model output into finding blocks on all-dash delimiter lines."""
    blocks: list[str] = []
    current: list[str] = []
    for line in raw.splitlines():
        if _DELIMITER_RE.match(line):
            blocks.append("\n".join(current))
            current = []
        else:
            current.append(line)
    blocks.append("\n".join(current))
    return blocks


def _parse_line_number(value: str) -> int | None:
    """Parse a LINE field value into an int, tolerating ranges and 'unknown'."""
    match = _FIRST_INT_RE.search(value)
    return int(match.group()) if match else None


def _clean_value(value: str) -> str:
    """Return a field value, treating placeholder ellipses ('...', '…') as empty."""
    stripped = value.strip()
    if stripped.strip(".…") == "":
        return ""
    return stripped


def parse_ai_response(raw: str, *, source: str = "llm") -> list[ReviewFinding]:
    """Parse the structured AI output into a list of ReviewFinding objects.

    Supports both the security-review format (fields SEVERITY / TITLE / FILE /
    LINE / CLASS / DESCRIPTION / PROOF / FIX, delimiter ``----``) and the legacy
    format (FILE / LINE / SEVERITY / ISSUE / FIX, delimiter ``---``).

    Malformed finding blocks are skipped with a warning rather than raising.
    A ``SEVERITY: NONE`` block (clean-code sentinel) yields no findings.

    Args:
        raw: The raw string returned by the AI model.
        source: Provenance recorded on each finding ("llm" or "semgrep").

    Returns:
        A (possibly empty) list of :class:`ReviewFinding` instances.
    """
    raw = raw.strip()
    if not raw or raw == _NO_ISSUES_SENTINEL:
        return []

    findings: list[ReviewFinding] = []

    for block in _split_blocks(raw):
        block = block.strip()
        if not block:
            continue

        parsed: dict[str, str] = {}
        for line in block.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                parsed[key.strip().upper()] = value.strip()

        severity_raw = parsed.get("SEVERITY", "").upper()

        # Clean-code sentinel — not a finding.
        if severity_raw == "NONE":
            continue

        if severity_raw not in _VALID_SEVERITIES:
            logger.warning(
                "Skipping finding block with invalid severity: %s (%s)",
                severity_raw or "(missing)",
                block[:80],
            )
            continue

        file_path = _clean_value(parsed.get("FILE", ""))
        if not file_path:
            logger.warning("Skipping finding block with no FILE: %s", block[:80])
            continue

        # DESCRIPTION (new) or ISSUE (legacy) both map to the description field.
        description = _clean_value(parsed.get("DESCRIPTION") or parsed.get("ISSUE") or "")
        title = _clean_value(parsed.get("TITLE", ""))
        proof = _clean_value(parsed.get("PROOF", ""))
        suggestion = _clean_value(parsed.get("FIX", ""))

        # A block with no real content (e.g. the model echoed the "..." template)
        # is noise, not a finding — skip it rather than emit a junk CRITICAL.
        if not description and not title and not proof:
            logger.warning("Skipping placeholder/empty finding block: %s", block[:80])
            continue

        finding = ReviewFinding(
            severity=severity_raw,  # type: ignore[arg-type]
            file_path=file_path,
            line_number=_parse_line_number(parsed.get("LINE", "")),
            issue=description,
            suggestion=suggestion,
            title=title,
            finding_class=FindingClass.from_str(parsed.get("CLASS")),
            proof=proof,
            source=source,  # type: ignore[arg-type]
        )
        findings.append(finding)

    return findings


def trim_diff(diff: str, max_chars: int) -> tuple[str, bool]:
    """Trim a diff to at most max_chars characters, cutting only at line boundaries.

    Args:
        diff: The raw diff string to trim.
        max_chars: Maximum number of characters to allow.

    Returns:
        A tuple of (trimmed_diff, was_trimmed).
    """
    if len(diff) <= max_chars:
        return diff, False

    lines = diff.splitlines(keepends=True)
    result: list[str] = []
    total = 0
    for line in lines:
        if total + len(line) > max_chars:
            break
        result.append(line)
        total += len(line)

    return "".join(result), True


def is_reviewable(diff: str) -> bool:
    """Return True if the diff contains reviewable content.

    Args:
        diff: The raw diff string to evaluate.

    Returns:
        False if the diff is empty, whitespace-only, or contains only binary markers.
    """
    stripped = diff.strip()
    if not stripped:
        return False
    lines = stripped.splitlines()
    non_binary = [
        line for line in lines if not any(line.startswith(marker) for marker in _BINARY_MARKERS)
    ]
    return bool(non_binary)
