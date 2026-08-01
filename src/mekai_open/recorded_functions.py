"""Typed package-internal boundary for recorded built-in executors."""

from __future__ import annotations

from typing import Protocol

from .contracts import FunctionResult
from .observations import NormalizedCaptureSummary, RecordedObservation

STATE_CARRY_FORWARD_NS = 30_000_000_000
MAX_VDA_HEADER_ID = (1 << 32) - 1


class RecordedFunctionExecutor(Protocol):
    """Define the common lifecycle of one recorded built-in calculation."""

    def consume(self, observation: RecordedObservation) -> None:
        """Consume one normalized observation in original input order."""

        ...

    def finish(
        self, summary: NormalizedCaptureSummary | None
    ) -> FunctionResult:
        """Finalize after verified exhaustion or an input-mutation failure."""

        ...
