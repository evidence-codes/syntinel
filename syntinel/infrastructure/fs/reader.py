from pathlib import Path

import pathspec

from syntinel.domain.scan_rules import DEFAULT_EXCLUDE_DIRS, is_reviewable_path


def _load_gitignore(root: Path) -> pathspec.PathSpec:
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return pathspec.PathSpec.from_lines("gitwildmatch", [])
    return pathspec.PathSpec.from_lines(
        "gitwildmatch", gitignore.read_text(encoding="utf-8", errors="ignore").splitlines()
    )


def discover_files(root: str, *, max_files: int | None = None) -> list[Path]:
    """Walk `root`, returning reviewable file paths not excluded by .gitignore
    or the default exclude-dir list.

    Files are ordered by size (largest first) as a proxy for "most likely to
    contain meaningful logic" when `max_files` truncates the set.
    """
    root_path = Path(root).resolve()
    spec = _load_gitignore(root_path)

    candidates: list[Path] = []
    for path in root_path.rglob("*"):
        if not path.is_file():
            continue
        if any(part in DEFAULT_EXCLUDE_DIRS for part in path.parts):
            continue
        if not is_reviewable_path(path.name):
            continue
        relative = path.relative_to(root_path)
        if spec.match_file(str(relative)):
            continue
        candidates.append(path)

    candidates.sort(key=lambda p: p.stat().st_size, reverse=True)

    if max_files is not None:
        candidates = candidates[:max_files]

    return candidates
