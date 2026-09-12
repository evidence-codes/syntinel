from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    groq_api_key: str = ""
    groq_model: str = "qwen-2.5-coder-32b"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    # Some models (e.g. Kimi's reasoning models) only accept temperature=1.
    groq_temperature: float = 0.0

    # Full-repo CLI path: max characters per LLM chunk sent for review.
    max_chunk_chars: int = 24000
    # Number of concurrent in-flight LLM chunk reviews during a scan.
    scan_concurrency: int = 5
    # Minimum seconds between successive LLM call starts (paces low-RPM tiers).
    min_request_interval_seconds: float = 0.0
    # On-disk cache directory for scan results keyed by content hash.
    cache_dir: str = ".syntinel_cache"

    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()
