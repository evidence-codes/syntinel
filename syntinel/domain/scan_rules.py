from dataclasses import dataclass

# File extensions Syntinel considers reviewable. Kept intentionally narrow for
# Phase 2 — broaden as language support is validated.
REVIEWABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".java",
        ".php", ".rs", ".c", ".cpp", ".h", ".hpp", ".cs",
    }
)

# Directories never worth scanning regardless of .gitignore contents.
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        ".git", ".venv", "venv", "node_modules", "dist", "build",
        "__pycache__", ".pytest_cache", ".ruff_cache", ".syntinel_cache",
        "vendor", "target",
    }
)


@dataclass(slots=True)
class Chunk:
    """A slice of a source file sized to fit one LLM review request."""

    file_path: str
    content: str
    start_line: int
    end_line: int


def is_reviewable_path(path: str) -> bool:
    """Return True if the file extension is one Syntinel reviews."""
    lowered = path.lower()
    return any(lowered.endswith(ext) for ext in REVIEWABLE_EXTENSIONS)


def chunk_file(file_path: str, content: str, max_chars: int) -> list[Chunk]:
    """Split a file's content into line-bounded chunks of at most max_chars.

    A single chunk is preferred (functions read best whole); a file only
    splits when it exceeds max_chars, and splits fall on line boundaries so a
    chunk never truncates mid-statement.
    """
    if len(content) <= max_chars:
        lines = content.splitlines()
        return [Chunk(file_path=file_path, content=content, start_line=1, end_line=len(lines) or 1)]

    lines = content.splitlines(keepends=True)
    chunks: list[Chunk] = []
    current: list[str] = []
    current_len = 0
    start_line = 1

    for i, line in enumerate(lines, start=1):
        if current and current_len + len(line) > max_chars:
            chunks.append(
                Chunk(
                    file_path=file_path,
                    content="".join(current),
                    start_line=start_line,
                    end_line=i - 1,
                )
            )
            current = []
            current_len = 0
            start_line = i
        current.append(line)
        current_len += len(line)

    if current:
        chunks.append(
            Chunk(
                file_path=file_path,
                content="".join(current),
                start_line=start_line,
                end_line=len(lines),
            )
        )

    return chunks
