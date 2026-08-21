class SyntinelError(Exception):
    """Base exception for all Syntinel application errors."""

    def __init__(self, message: str, detail: dict | None = None) -> None:
        super().__init__(message)
        self.detail = detail or {}


class AIClientError(SyntinelError):
    """Raised when the model API returns a non-2xx response or an unexpected payload."""


class ScanError(SyntinelError):
    """Raised when a scan cannot be completed for a repository or file."""
