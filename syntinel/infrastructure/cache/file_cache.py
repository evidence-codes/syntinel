import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from syntinel.domain.models import FindingClass, ReviewFinding


def cache_key(*, content: str, prompt_version: str, model: str) -> str:
    """Return a stable content-hash cache key for one chunk review."""
    digest = hashlib.sha256()
    digest.update(content.encode("utf-8"))
    digest.update(b"|")
    digest.update(prompt_version.encode("utf-8"))
    digest.update(b"|")
    digest.update(model.encode("utf-8"))
    return digest.hexdigest()


class FileCache:
    """On-disk JSON cache of chunk-review results, keyed by content hash."""

    def __init__(self, cache_dir: str) -> None:
        self._dir = Path(cache_dir)

    def get(self, key: str) -> list[ReviewFinding] | None:
        path = self._dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        return [
            ReviewFinding(
                **{**item, "finding_class": FindingClass.from_str(item.get("finding_class"))}
            )
            for item in raw
        ]

    def set(self, key: str, findings: list[ReviewFinding]) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / f"{key}.json"
        payload = [{**asdict(f), "finding_class": f.finding_class.value} for f in findings]
        path.write_text(json.dumps(payload), encoding="utf-8")
