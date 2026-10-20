"""LLM backend for a local Ollama server."""

import os
import re

import httpx

from .base import LLMBackend, LLMError

# Reasoning models (e.g. qwen3) may wrap their chain of thought in <think> tags.
THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL)


class OllamaBackend(LLMBackend):
    """Calls Ollama's ``POST /api/generate`` (non-streaming).

    Configured by ``OLLAMA_URL`` and ``OLLAMA_MODEL``; ``LLM_TIMEOUT`` (seconds)
    bounds each request, since local models can be slow.
    """

    name = "ollama"

    def __init__(self, url: str | None = None, model: str | None = None, timeout: float | None = None):
        self.url = (url or os.environ.get("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL", "qwen3:8b")
        self.timeout = timeout or float(os.environ.get("LLM_TIMEOUT", "120"))

    def generate(self, prompt: str) -> str:
        try:
            resp = httpx.post(
                f"{self.url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise LLMError(f"Ollama at {self.url} is unreachable: {exc}") from exc
        if resp.is_error:
            raise LLMError(f"Ollama returned {resp.status_code}: {resp.text.strip()}")
        text = resp.json().get("response")
        if not isinstance(text, str):
            raise LLMError("Ollama response has no 'response' text")
        return THINK_BLOCK.sub("", text).strip()
