"""Bound interval detail while preserving defensible union arithmetic."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import EvaluationWindow


@dataclass(frozen=True, slots=True)
class BoundedInterval:
    """Represent one non-empty half-open interval with a stable reason."""

    start_ns: int
    end_ns: int
    reason: str

    def __post_init__(self) -> None:
        if self.start_ns < 0 or self.end_ns <= self.start_ns:
            raise ValueError("bounded interval must be positive and non-empty")
        if not self.reason:
            raise ValueError("bounded interval requires a reason")

    def to_dict(self) -> dict[str, int | str]:
        """Return the JSON-compatible interval representation."""

        return {
            "start_ns": self.start_ns,
            "end_ns": self.end_ns,
            "reason": self.reason,
        }


class BoundedIntervalAccumulator:
    """Retain bounded coordinates and an exact forward-order union scalar."""

    def __init__(self, detail_limit: int) -> None:
        """Initialize an empty accumulator with a non-negative detail limit."""

        if isinstance(detail_limit, bool) or not isinstance(detail_limit, int):
            raise TypeError("interval detail limit must be an integer")
        if detail_limit < 0:
            raise ValueError("interval detail limit cannot be negative")
        self._detail_limit = detail_limit
        self._details: list[BoundedInterval] = []
        self._known_interval_count = 0
        self._details_truncated = False
        self._union_tail: tuple[int, int] | None = None
        self._union_duration_ns = 0
        self._starts_forward_ordered = True
        self._last_start_ns: int | None = None
        self._minimum_start_ns: int | None = None
        self._maximum_end_ns: int | None = None

    @property
    def known_interval_count(self) -> int:
        """Return the number of non-empty intervals presented to the boundary."""

        return self._known_interval_count

    @property
    def details_truncated(self) -> bool:
        """Return whether at least one interval coordinate was omitted."""

        return self._details_truncated

    def add(self, start_ns: int, end_ns: int, reason: str) -> bool:
        """Accumulate one interval and return whether detail first truncated."""

        if end_ns <= start_ns:
            return False
        interval = BoundedInterval(start_ns, end_ns, reason)
        self._known_interval_count += 1
        self._accumulate_forward_union(start_ns, end_ns)
        first_truncation = False
        if len(self._details) < self._detail_limit:
            self._details.append(interval)
        else:
            first_truncation = not self._details_truncated
            self._details_truncated = True
        return first_truncation

    def retained_intervals(
        self, window: EvaluationWindow
    ) -> tuple[BoundedInterval, ...]:
        """Return clipped, deterministically merged retained coordinates."""

        clipped = sorted(
            (
                max(window.start_ns, item.start_ns),
                min(window.end_ns, item.end_ns),
                item.reason,
            )
            for item in self._details
            if min(window.end_ns, item.end_ns)
            > max(window.start_ns, item.start_ns)
        )
        merged: list[BoundedInterval] = []
        for start_ns, end_ns, reason in clipped:
            if (
                merged
                and reason == merged[-1].reason
                and start_ns <= merged[-1].end_ns
            ):
                previous = merged[-1]
                merged[-1] = BoundedInterval(
                    previous.start_ns,
                    max(previous.end_ns, end_ns),
                    reason,
                )
            else:
                merged.append(BoundedInterval(start_ns, end_ns, reason))
        return tuple(merged)

    def exact_union_duration_ns(
        self, window: EvaluationWindow
    ) -> int | None:
        """Return the exact clipped union or withhold an unsupported scalar."""

        if not self._details_truncated:
            intervals = sorted(
                (
                    max(window.start_ns, item.start_ns),
                    min(window.end_ns, item.end_ns),
                )
                for item in self._details
                if min(window.end_ns, item.end_ns)
                > max(window.start_ns, item.start_ns)
            )
            total = 0
            tail: tuple[int, int] | None = None
            for start_ns, end_ns in intervals:
                if tail is None or start_ns > tail[1]:
                    total += end_ns - start_ns
                    tail = (start_ns, end_ns)
                    continue
                if end_ns > tail[1]:
                    total += end_ns - tail[1]
                    tail = (tail[0], end_ns)
            return total
        if self._truncated_scalar_is_exact(window):
            return self._union_duration_ns
        return None

    def _accumulate_forward_union(self, start_ns: int, end_ns: int) -> None:
        """Update constant-memory union state while starts remain ordered."""

        previous_start = self._last_start_ns
        if previous_start is not None and start_ns < previous_start:
            self._starts_forward_ordered = False
        self._last_start_ns = start_ns
        if self._minimum_start_ns is None:
            self._minimum_start_ns = start_ns
            self._maximum_end_ns = end_ns
        else:
            self._minimum_start_ns = min(self._minimum_start_ns, start_ns)
            assert self._maximum_end_ns is not None
            self._maximum_end_ns = max(self._maximum_end_ns, end_ns)
        if not self._starts_forward_ordered:
            return

        tail = self._union_tail
        if tail is None:
            self._union_tail = (start_ns, end_ns)
            self._union_duration_ns += end_ns - start_ns
        elif start_ns <= tail[1]:
            self._union_duration_ns += max(0, end_ns - tail[1])
            self._union_tail = (tail[0], max(tail[1], end_ns))
        else:
            self._union_duration_ns += end_ns - start_ns
            self._union_tail = (start_ns, end_ns)

    def _truncated_scalar_is_exact(self, window: EvaluationWindow) -> bool:
        """Check the invariants that make the forward scalar exact."""

        return (
            self._starts_forward_ordered
            and self._minimum_start_ns is not None
            and self._maximum_end_ns is not None
            and self._minimum_start_ns >= window.start_ns
            and self._maximum_end_ns <= window.end_ns
            and self._union_duration_ns <= window.duration_ns
        )
