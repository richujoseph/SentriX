"""Common interface for the LLM backends used to summarise incidents."""

from abc import ABC, abstractmethod


class LLMError(Exception):
    """The backend could not produce a completion (unreachable, bad config, bad response)."""


class LLMBackend(ABC):
    """A text-in, text-out language model."""

    name: str

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Return the model's completion for ``prompt``.

        Blocking; call it via ``asyncio.to_thread`` from async code.

        Raises:
            LLMError: If the backend fails or returns an unusable response.
        """
