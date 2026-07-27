"""Consume OpenAI-compatible text streams without logging or persistence."""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterable, Iterable
from typing import Any


def _delta_text(chunk: Any) -> list[str]:
    parts: list[str] = []
    for choice in getattr(chunk, "choices", ()):
        content = getattr(getattr(choice, "delta", None), "content", None)
        if isinstance(content, str):
            parts.append(content)
    return parts


def consume_openai_v1_stream(response: Iterable[Any]) -> str:
    """Return concatenated text deltas while keeping raw chunks memory-only."""
    parts: list[str] = []
    try:
        for chunk in response:
            parts.extend(_delta_text(chunk))
        return "".join(parts).strip()
    finally:
        parts.clear()
        close = getattr(response, "close", None)
        if callable(close):
            close()


async def consume_openai_v1_stream_async(response: AsyncIterable[Any]) -> str:
    """Async variant of consume_openai_v1_stream."""
    parts: list[str] = []
    try:
        async for chunk in response:
            parts.extend(_delta_text(chunk))
        return "".join(parts).strip()
    finally:
        parts.clear()
        close = getattr(response, "aclose", None) or getattr(response, "close", None)
        if callable(close):
            result = close()
            if inspect.isawaitable(result):
                await result
