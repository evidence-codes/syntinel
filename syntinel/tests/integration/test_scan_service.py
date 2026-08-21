import httpx
import respx

from syntinel.core.config import Settings
from syntinel.services.scan_service import ScanOptions, ScanService

_CRITICAL_RESPONSE = """SEVERITY: CRITICAL
TITLE: No null check
FILE: {file}
LINE: 1
CLASS: logic
DESCRIPTION: amount can be None
PROOF: foo(None)
FIX: validate input
----
"""


@respx.mock
async def test_scan_finds_llm_and_semgrep_findings(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("def foo(amount):\n    return amount + 1\n", encoding="utf-8")

    respx.post("https://api.groq.com/openai/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": _CRITICAL_RESPONSE.format(file=str(target))}}
                ]
            },
        )
    )

    settings = Settings(groq_api_key="test-key")
    service = ScanService(settings)
    options = ScanOptions(use_semgrep=False, use_cache=False)

    report = await service.scan(str(tmp_path), options)

    assert report.files_scanned == 1
    assert report.has_critical
    assert report.findings[0].file_path == str(target)


async def test_scan_without_api_key_skips_llm_pass(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("def foo():\n    pass\n", encoding="utf-8")

    settings = Settings(groq_api_key="")
    service = ScanService(settings)
    options = ScanOptions(use_semgrep=False, use_cache=False)

    report = await service.scan(str(tmp_path), options)

    assert report.files_scanned == 1
    assert report.findings == []


async def test_scan_respects_severity_filter(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("def foo():\n    pass\n", encoding="utf-8")

    settings = Settings(groq_api_key="")
    service = ScanService(settings)
    options = ScanOptions(use_semgrep=False, use_llm=False, min_severity="critical")

    report = await service.scan(str(tmp_path), options)

    assert report.findings == []
