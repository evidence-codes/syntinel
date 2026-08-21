import asyncio
import json
import shutil

from syntinel.core.logging import get_logger
from syntinel.domain.models import FindingClass, ReviewFinding

logger = get_logger(__name__)

DEFAULT_CONFIGS: tuple[str, ...] = ("p/security-audit", "p/secrets")

_SEMGREP_TO_SEVERITY: dict[str, str] = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


class SemgrepScanner:
    """Wraps the `semgrep` CLI. Degrades gracefully when it isn't installed."""

    def __init__(self, configs: tuple[str, ...] = DEFAULT_CONFIGS) -> None:
        self._configs = configs

    @property
    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    async def scan_paths(self, paths: list[str]) -> list[ReviewFinding]:
        """Run Semgrep against the given paths and return parsed findings.

        Returns an empty list (with a warning logged) if Semgrep is not
        installed or the run fails — the scan continues LLM-only.
        """
        if not self.available:
            logger.warning("semgrep not found on PATH — skipping deterministic scan")
            return []
        if not paths:
            return []

        cmd = ["semgrep", "--json", "--quiet"]
        for config in self._configs:
            cmd += ["--config", config]
        cmd += paths

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except OSError as exc:
            logger.warning("semgrep invocation failed: %s", exc)
            return []

        if not stdout:
            if stderr:
                err = stderr.decode(errors="replace")[:300]
                logger.warning("semgrep produced no output: %s", err)
            return []

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning("semgrep produced non-JSON output — skipping")
            return []

        return [self._to_finding(result) for result in payload.get("results", [])]

    @staticmethod
    def _to_finding(result: dict) -> ReviewFinding:
        severity = _SEMGREP_TO_SEVERITY.get(
            result.get("extra", {}).get("severity", "WARNING"), "MEDIUM"
        )
        check_id = result.get("check_id", "semgrep-rule")
        message = result.get("extra", {}).get("message", check_id)
        finding_class = FindingClass.SECRETS if "secret" in check_id.lower() else FindingClass.OTHER

        return ReviewFinding(
            severity=severity,  # type: ignore[arg-type]
            file_path=result.get("path", "unknown"),
            line_number=result.get("start", {}).get("line"),
            issue=message,
            title=check_id,
            finding_class=finding_class,
            source="semgrep",
        )
