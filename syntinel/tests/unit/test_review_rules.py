from syntinel.domain.review_rules import is_reviewable, parse_ai_response, trim_diff


def test_parse_ai_response_single_finding():
    raw = """SEVERITY: CRITICAL
TITLE: Null amount crashes payment
FILE: src/pay.py
LINE: 42
CLASS: logic
DESCRIPTION: No null check before arithmetic.
PROOF: process_payment(amount=None) raises AttributeError
FIX: Validate amount is not None before use.
----
"""
    findings = parse_ai_response(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "CRITICAL"
    assert f.file_path == "src/pay.py"
    assert f.line_number == 42
    assert f.finding_class.value == "logic"


def test_parse_ai_response_multiple_findings():
    raw = (
        "SEVERITY: HIGH\nTITLE: SQLi\nFILE: a.py\nLINE: 1\nCLASS: injection\n"
        "DESCRIPTION: concat\nPROOF: x\nFIX: parametrize\n----\n"
        "SEVERITY: LOW\nTITLE: Weak log\nFILE: b.py\nLINE: 5\nCLASS: other\n"
        "DESCRIPTION: verbose\nPROOF: y\nFIX: redact\n----\n"
    )
    findings = parse_ai_response(raw)
    assert [f.file_path for f in findings] == ["a.py", "b.py"]


def test_parse_ai_response_no_issues_sentinel():
    assert parse_ai_response("NO_ISSUES_FOUND") == []
    assert parse_ai_response("") == []


def test_parse_ai_response_severity_none_block():
    raw = "SEVERITY: NONE\n----\n"
    assert parse_ai_response(raw) == []


def test_parse_ai_response_skips_invalid_severity():
    raw = "SEVERITY: BOGUS\nFILE: a.py\nDESCRIPTION: x\n----\n"
    assert parse_ai_response(raw) == []


def test_parse_ai_response_skips_missing_file():
    raw = "SEVERITY: HIGH\nDESCRIPTION: x\n----\n"
    assert parse_ai_response(raw) == []


def test_parse_ai_response_legacy_format():
    raw = "FILE: legacy.py\nLINE: 3\nSEVERITY: MEDIUM\nISSUE: old style\nFIX: fix it\n---\n"
    findings = parse_ai_response(raw)
    assert len(findings) == 1
    assert findings[0].issue == "old style"


def test_trim_diff_no_trim_needed():
    diff = "short diff"
    trimmed, was_trimmed = trim_diff(diff, max_chars=100)
    assert trimmed == diff
    assert was_trimmed is False


def test_trim_diff_cuts_on_line_boundary():
    diff = "line one\nline two\nline three\n"
    trimmed, was_trimmed = trim_diff(diff, max_chars=17)
    assert was_trimmed is True
    assert trimmed == "line one\n"
    assert "line two" not in trimmed


def test_is_reviewable_empty():
    assert is_reviewable("") is False
    assert is_reviewable("   \n  ") is False


def test_is_reviewable_binary_only():
    assert is_reviewable("Binary files a/x.png and b/x.png differ") is False


def test_is_reviewable_real_diff():
    assert is_reviewable("+def foo():\n+    pass\n") is True
