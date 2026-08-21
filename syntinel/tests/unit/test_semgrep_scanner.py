from syntinel.infrastructure.scanners.semgrep_scanner import SemgrepScanner


def test_to_finding_maps_error_severity_to_high():
    result = {
        "check_id": "python.lang.security.sql-injection",
        "path": "app/db.py",
        "start": {"line": 12},
        "extra": {"severity": "ERROR", "message": "possible SQL injection"},
    }
    finding = SemgrepScanner._to_finding(result)
    assert finding.severity == "HIGH"
    assert finding.file_path == "app/db.py"
    assert finding.line_number == 12
    assert finding.source == "semgrep"


def test_to_finding_flags_secrets_class():
    result = {
        "check_id": "generic.secrets.hardcoded-api-key",
        "path": "app/config.py",
        "start": {"line": 3},
        "extra": {"severity": "WARNING", "message": "hardcoded secret"},
    }
    finding = SemgrepScanner._to_finding(result)
    assert finding.finding_class.value == "secrets"
    assert finding.severity == "MEDIUM"


async def test_scan_paths_returns_empty_when_unavailable(monkeypatch):
    scanner = SemgrepScanner()
    monkeypatch.setattr(SemgrepScanner, "available", property(lambda self: False))
    result = await scanner.scan_paths(["some/file.py"])
    assert result == []
