"""Pick the LLM backend named by the LLM_BACKEND env var."""

import os

from .base import LLMBackend
from .cloud_backend import CloudBackend
from .ollama_backend import OllamaBackend

BACKENDS: dict[str, type[LLMBackend]] = {
    OllamaBackend.name: OllamaBackend,
    CloudBackend.name: CloudBackend,
}
DEFAULT_BACKEND = OllamaBackend.name


def get_llm_backend(name: str | None = None) -> LLMBackend:
    """Return a backend instance by name, defaulting to ``LLM_BACKEND``, then ollama.

    Raises:
        ValueError: If the name isn't a known backend.
    """
    key = (name or os.environ.get("LLM_BACKEND") or DEFAULT_BACKEND).strip().lower()
    try:
        return BACKENDS[key]()
    except KeyError:
        raise ValueError(f"Unknown LLM_BACKEND {key!r}; choose one of: {', '.join(BACKENDS)}") from None
