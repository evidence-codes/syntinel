import re
from types import TracebackType

import httpx

from syntinel.core.exceptions import AIClientError
from syntinel.core.logging import get_logger

logger = get_logger(__name__)

# Reasoning models (e.g. QwQ) emit a <think>...</think> block before the real
# answer. Strip it so the structured-finding parser only sees final output.
_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def strip_reasoning(text: str) -> str:
    """Remove any <think>...</think> reasoning block from a model response."""
    return _THINK_BLOCK_RE.sub("", text).strip()


class AIClient:
    """Thin async client over an OpenAI-compatible chat completions endpoint."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        max_diff_chars: int = 24000,
        timeout: float = 120.0,
        temperature: float = 0.0,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._max_diff_chars = max_diff_chars
        self._temperature = temperature
        self._client = httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self) -> "AIClient":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def complete(self, *, system_prompt: str, user_prompt: str) -> str:
        """Send a single chat-completion request and return the stripped response text.

        Raises:
            AIClientError: if the API key is missing, the request fails, or the
                response payload is malformed.
        """
        if not self._api_key:
            raise AIClientError("GROQ_API_KEY is not set")

        url = f"{self._base_url}/chat/completions"
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self._temperature,
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}

        try:
            response = await self._client.post(url, json=payload, headers=headers)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise AIClientError(
                f"Model API returned {exc.response.status_code}",
                detail={"body": exc.response.text[:500]},
            ) from exc
        except httpx.HTTPError as exc:
            raise AIClientError(f"Model API request failed: {exc}") from exc
        except OSError as exc:
            # Covers ssl.SSLError and other transport-level failures that
            # httpx doesn't wrap as HTTPError (e.g. connection reset mid-stream).
            raise AIClientError(f"Model API transport error: {exc}") from exc

        data = response.json()
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIClientError("Malformed response payload from model API") from exc

        return strip_reasoning(content)
