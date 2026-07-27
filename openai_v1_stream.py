"""Consume OpenAI-compatible text streams without logging or persistence."""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterable, Iterable
from contextlib import contextmanager
from typing import Any


def _append_delta(buffer: bytearray, chunk: Any) -> None:
    for choice in getattr(chunk, "choices", ()):
        content = getattr(getattr(choice, "delta", None), "content", None)
        if isinstance(content, str):
            buffer.extend(content.encode("utf-8"))


def wipe_bytearray(buffer: bytearray) -> None:
    """Overwrite a mutable buffer before releasing its storage."""
    buffer[:] = b"\0" * len(buffer)
    buffer.clear()


@contextmanager
def openai_v1_stream_buffer(response: Iterable[Any]):
    """Yield a mutable UTF-8 buffer and zero it immediately after use."""
    buffer = bytearray()
    try:
        for chunk in response:
            _append_delta(buffer, chunk)
            del chunk
        yield buffer
    finally:
        wipe_bytearray(buffer)
        close = getattr(response, "close", None)
        if callable(close):
            close()


def consume_openai_v1_stream(response: Iterable[Any]) -> str:
    """Return concatenated text deltas while keeping raw chunks memory-only."""
    with openai_v1_stream_buffer(response) as buffer:
        return buffer.decode("utf-8").strip()


async def consume_openai_v1_stream_async(response: AsyncIterable[Any]) -> str:
    """Async variant of consume_openai_v1_stream."""
    buffer = bytearray()
    try:
        async for chunk in response:
            _append_delta(buffer, chunk)
            del chunk
        return buffer.decode("utf-8").strip()
    finally:
        wipe_bytearray(buffer)
        close = getattr(response, "aclose", None) or getattr(response, "close", None)
        if callable(close):
            result = close()
            if inspect.isawaitable(result):
                await result
