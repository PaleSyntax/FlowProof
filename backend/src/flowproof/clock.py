"""Process-local UTC clock that never moves backwards.

Wall clocks may be resynchronized while Docker Desktop or a VM is under load.
State-machine timestamps still need UTC, but lease/deadline causality must follow
elapsed time rather than a backwards wall-clock step.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta


class MonotonicUtcClock:
    """Follow forward wall-clock corrections and bridge backwards steps monotonically."""

    def __init__(
        self,
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._lock = threading.Lock()
        self._last_utc = self._normalize(self._wall_clock())
        self._last_monotonic = self._monotonic_clock()

    @staticmethod
    def _normalize(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def __call__(self) -> datetime:
        with self._lock:
            monotonic_now = self._monotonic_clock()
            elapsed = max(monotonic_now - self._last_monotonic, 0.0)
            elapsed_floor = self._last_utc + timedelta(seconds=elapsed)
            wall_now = self._normalize(self._wall_clock())
            current = max(elapsed_floor, wall_now)
            self._last_utc = current
            self._last_monotonic = monotonic_now
            return current


_PROCESS_UTC_CLOCK = MonotonicUtcClock()


def monotonic_utc_now() -> datetime:
    """Return process-local UTC that preserves causal ordering across clock resyncs."""

    return _PROCESS_UTC_CLOCK()
