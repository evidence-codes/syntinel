from pathlib import Path


def read_user_file(base_dir: str, filename: str) -> str:
    # VULNERABLE: unsanitized filename allows path traversal ("../../etc/passwd").
    path = Path(base_dir) / filename
    return path.read_text()
