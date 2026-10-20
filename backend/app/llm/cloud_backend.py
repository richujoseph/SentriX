"""LLM backend for a hosted API (stub: Anthropic Messages API).

Minimal on purpose: one user message, no streaming, retries or tool use.
"""

import os

import httpx

from .base import LLMBackend, LLMError

ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class CloudBackend(LLMBackend):
    """Calls the Anthropic Messages API.

    Configured by ``ANTHROPIC_API_KEY`` (required), ``CLOUD_MODEL`` and
    ``CLOUD_MAX_TOKENS``; ``LLM_TIMEOUT`` (seconds) bounds each request.
    """

    name = "cloud"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
        timeout: float | None = None,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or os.environ.get("CLOUD_MODEL", "claude-sonnet-5-5")
        self.max_tokens = max_tokens or int(os.environ.get("CLOUD_MAX_TOKENS", "1024"))
        self.timeout = timeout or float(os.environ.get("LLM_TIMEOUT", "120"))

    def generate(self, prompt: str) -> str:
        if not self.api_key:
            raise LLMError("ANTHROPIC_API_KEY is not set")
        try:
            resp = httpx.post(
                ANTHROPIC_MESSAGES_URL,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": ANTHROPIC_VERSION,
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": self.max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise LLMError(f"Cloud LLM API is unreachable: {exc}") from exc
        if resp.is_error:
            raise LLMError(f"Cloud LLM API returned {resp.status_code}: {resp.text.strip()}")
        blocks = resp.json().get("content", [])
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        if not text:
            raise LLMError("Cloud LLM response has no text content")
        return text.strip()
