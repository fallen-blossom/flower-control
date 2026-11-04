"""Internal finite-decision adapter boundary; this is not a driver framework.

Jev and Perplexity Decisions share this interface. Any provider must adapt to
these bounded primitives, preserve cancellation and privacy, and cannot supply
executable text, grant permissions, or acquire local execution privileges.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol

from .targets import TargetRequest, JevTargetSelection


class DecisionClient(Protocol):
    input_capabilities: object

    async def choose_scheduling(self, request, *, deadline: float,
                                permitted: Callable[[], Awaitable[bool]]): ...

    async def choose_target(self, request: TargetRequest, *, deadline: float,
                            permitted: Callable[[], Awaitable[bool]],
                            fresh: Callable[[], Awaitable[bool]]) -> JevTargetSelection: ...

    async def ask_batch(self, state, questions, *, deadline: float,
                        permitted: Callable[[], Awaitable[bool]],
                        fresh: Callable[[], Awaitable[bool]], max_attempts=2,
                        total_budget=5.0): ...

    async def close(self) -> None: ...
