from typer.testing import CliRunner

from syntinel.cli.main import app

runner = CliRunner()


def test_scan_no_llm_no_semgrep_produces_report(tmp_path):
    (tmp_path / "app.py").write_text("def foo():\n    pass\n", encoding="utf-8")
    output = tmp_path / "report"

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--no-llm", "--no-semgrep", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    assert (tmp_path / "report.md").exists()
    assert "issue(s) found" in result.output


def test_scan_json_format(tmp_path):
    (tmp_path / "app.py").write_text("def foo():\n    pass\n", encoding="utf-8")
    output = tmp_path / "report"

    args = [
        "scan", str(tmp_path), "--no-llm", "--no-semgrep",
        "--output", str(output), "--format", "json",
    ]
    result = runner.invoke(app, args)

    assert result.exit_code == 0, result.output
    assert (tmp_path / "report.json").exists()


def test_scan_rejects_invalid_severity(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--severity", "extreme"])
    assert result.exit_code == 2
