import json
from dataclasses import asdict
from datetime import UTC, datetime

from syntinel.domain.models import ScanReport

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def render_json(report: ScanReport) -> str:
    """Render a ScanReport as a JSON string."""
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "files_scanned": report.files_scanned,
        "duration_seconds": report.duration_seconds,
        "findings": [
            {**asdict(f), "finding_class": f.finding_class.value} for f in report.findings
        ],
        "skipped": [asdict(s) for s in report.skipped],
    }
    return json.dumps(payload, indent=2)


def render_markdown(report: ScanReport, *, target: str = ".") -> str:
    """Render a ScanReport as a client-readable Markdown audit report."""
    findings = sorted(report.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in _SEVERITY_ORDER}

    lines = [
        "# Syntinel Security Report",
        "",
        f"**Target:** `{target}`  ",
        f"**Generated:** {datetime.now(UTC).isoformat()}  ",
        f"**Files scanned:** {report.files_scanned}  ",
        f"**Duration:** {report.duration_seconds:.1f}s",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {sev} | {counts[sev]} |")
    lines += ["", f"**Total findings:** {len(findings)}", ""]

    if not findings:
        lines.append("No issues found.")
    else:
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            location = f.file_path + (f":{f.line_number}" if f.line_number else "")
            lines.append(f"### [{f.severity}] {f.title or f.issue[:60]}")
            lines.append("")
            lines.append(f"- **File:** `{location}`")
            lines.append(f"- **Class:** {f.finding_class.value}")
            lines.append(f"- **Source:** {f.source}")
            lines.append(f"- **Issue:** {f.issue}")
            if f.proof:
                lines.append(f"- **Proof:** {f.proof}")
            if f.suggestion:
                lines.append(f"- **Fix:** {f.suggestion}")
            lines.append("")

    if report.skipped:
        lines.append("## Skipped Files")
        lines.append("")
        for s in report.skipped:
            lines.append(f"- `{s.path}` — {s.reason}")

    return "\n".join(lines)
