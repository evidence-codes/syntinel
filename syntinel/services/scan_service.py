import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from syntinel.core.config import Settings
from syntinel.core.exceptions import AIClientError
from syntinel.core.logging import get_logger
from syntinel.domain import review_rules, scan_rules
from syntinel.domain.models import ReviewFinding, ScanReport, SkippedFile, severity_at_least
from syntinel.infrastructure.ai.client import AIClient
from syntinel.infrastructure.ai.security_prompts import (
    PROMPT_VERSION,
    SECURITY_REVIEW_SYSTEM_PROMPT,
    build_review_prompt,
)
from syntinel.infrastructure.cache.file_cache import FileCache, cache_key
from syntinel.infrastructure.fs.reader import discover_files
from syntinel.infrastructure.scanners.semgrep_scanner import SemgrepScanner

logger = get_logger(__name__)


class _RequestPacer:
    """Enforces a minimum gap between successive LLM call starts (for low-RPM tiers)."""

    def __init__(self, min_interval_seconds: float) -> None:
        self._min_interval = min_interval_seconds
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def wait_turn(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self._min_interval
        if delay:
            await asyncio.sleep(delay)


@dataclass(slots=True)
class ScanOptions:
    """User-facing knobs for a scan run."""

    max_files: int | None = None
    min_severity: str = "low"
    use_semgrep: bool = True
    use_llm: bool = True
    use_cache: bool = True
    concurrency: int = 5


@dataclass(slots=True)
class ScanCallbacks:
    """Optional progress hooks the CLI wires up for its progress bar."""

    on_file_start: Callable[[str], None] = field(default=lambda _: None)
    on_file_done: Callable[[str], None] = field(default=lambda _: None)


class ScanService:
    """Orchestrates file discovery, the Semgrep pass, and the LLM review pass."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def scan(
        self,
        root: str,
        options: ScanOptions,
        callbacks: ScanCallbacks | None = None,
    ) -> ScanReport:
        callbacks = callbacks or ScanCallbacks()
        started = time.monotonic()

        files = discover_files(root, max_files=options.max_files)
        skipped: list[SkippedFile] = []

        semgrep_findings: list[ReviewFinding] = []
        if options.use_semgrep:
            scanner = SemgrepScanner()
            if not scanner.available:
                skipped.append(SkippedFile(path=root, reason="semgrep not installed"))
            else:
                semgrep_findings = await scanner.scan_paths([str(f) for f in files])

        llm_findings: list[ReviewFinding] = []
        if options.use_llm:
            llm_findings = await self._run_llm_pass(files, options, callbacks)
        else:
            for f in files:
                callbacks.on_file_start(str(f))
                callbacks.on_file_done(str(f))

        merged = _merge_findings(llm_findings, semgrep_findings)
        merged = [f for f in merged if severity_at_least(f.severity, options.min_severity)]

        return ScanReport(
            findings=merged,
            skipped=skipped,
            files_scanned=len(files),
            duration_seconds=time.monotonic() - started,
        )

    async def _run_llm_pass(
        self, files: list, options: ScanOptions, callbacks: ScanCallbacks
    ) -> list[ReviewFinding]:
        if not self._settings.groq_api_key:
            logger.warning("GROQ_API_KEY not set — skipping LLM review pass")
            return []

        cache = FileCache(self._settings.cache_dir) if options.use_cache else None
        client = AIClient(
            api_key=self._settings.groq_api_key,
            base_url=self._settings.groq_base_url,
            model=self._settings.groq_model,
            temperature=self._settings.groq_temperature,
        )
        semaphore = asyncio.Semaphore(max(1, options.concurrency))
        pacer = _RequestPacer(self._settings.min_request_interval_seconds)
        findings: list[ReviewFinding] = []

        async def review_one(path) -> None:
            path_str = str(path)
            callbacks.on_file_start(path_str)
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                logger.warning("Could not read %s: %s", path_str, exc)
                callbacks.on_file_done(path_str)
                return

            for chunk in scan_rules.chunk_file(path_str, content, self._settings.max_chunk_chars):
                async with semaphore:
                    await pacer.wait_turn()
                    chunk_findings = await self._review_chunk(client, cache, chunk)
                findings.extend(chunk_findings)
            callbacks.on_file_done(path_str)

        try:
            await asyncio.gather(*(review_one(f) for f in files))
        finally:
            await client.aclose()

        return findings

    async def _review_chunk(
        self, client: AIClient, cache: FileCache | None, chunk
    ) -> list[ReviewFinding]:
        key = None
        if cache is not None:
            key = cache_key(
                content=chunk.content,
                prompt_version=PROMPT_VERSION,
                model=self._settings.groq_model,
            )
            cached = cache.get(key)
            if cached is not None:
                return cached

        prompt = build_review_prompt(chunk.file_path, chunk.content, start_line=chunk.start_line)

        @retry(
            retry=retry_if_exception_type(AIClientError),
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            reraise=True,
        )
        async def _call() -> str:
            return await client.complete(
                system_prompt=SECURITY_REVIEW_SYSTEM_PROMPT, user_prompt=prompt
            )

        try:
            raw = await _call()
        except AIClientError as exc:
            logger.warning("LLM review failed for %s: %s", chunk.file_path, exc)
            return []

        findings = review_rules.parse_ai_response(raw, source="llm")

        if cache is not None and key is not None:
            cache.set(key, findings)

        return findings


def _merge_findings(
    llm_findings: list[ReviewFinding], semgrep_findings: list[ReviewFinding]
) -> list[ReviewFinding]:
    """Merge and dedupe findings from both engines on (file, line, class).

    When both engines agree, the Semgrep finding is kept (deterministic, no
    inference cost) but the LLM's richer description/fix is preserved.
    """
    by_key: dict[tuple[str, int | None, str], ReviewFinding] = {}

    for finding in llm_findings:
        by_key[(finding.file_path, finding.line_number, finding.finding_class.value)] = finding

    for finding in semgrep_findings:
        key = (finding.file_path, finding.line_number, finding.finding_class.value)
        if key in by_key:
            existing = by_key[key]
            by_key[key] = ReviewFinding(
                severity=existing.severity,
                file_path=existing.file_path,
                line_number=existing.line_number,
                issue=existing.issue,
                suggestion=existing.suggestion,
                title=existing.title or finding.title,
                finding_class=existing.finding_class,
                proof=existing.proof,
                source="llm+semgrep",  # type: ignore[arg-type]
            )
        else:
            by_key[key] = finding

    return list(by_key.values())
