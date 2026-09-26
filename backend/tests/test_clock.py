from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flowproof.clock import MonotonicUtcClock


def test_monotonic_utc_clock_bridges_backward_wall_clock_step() -> None:
    wall = {"value": datetime(2026, 8, 24, 12, 0, tzinfo=UTC)}
    monotonic = {"value": 100.0}
    clock = MonotonicUtcClock(
        wall_clock=lambda: wall["value"],
        monotonic_clock=lambda: monotonic["value"],
    )

    first = clock()
    wall["value"] -= timedelta(seconds=40)
    monotonic["value"] += 5
    second = clock()
    monotonic["value"] += 7
    third = clock()

    assert second == first + timedelta(seconds=5)
    assert third == second + timedelta(seconds=7)


def test_monotonic_utc_clock_accepts_forward_wall_clock_correction() -> None:
    wall = {"value": datetime(2026, 8, 24, 12, 0, tzinfo=UTC)}
    monotonic = {"value": 200.0}
    clock = MonotonicUtcClock(
        wall_clock=lambda: wall["value"],
        monotonic_clock=lambda: monotonic["value"],
    )

    first = clock()
    wall["value"] += timedelta(seconds=30)
    monotonic["value"] += 1
    corrected = clock()
    monotonic["value"] += 2
    after = clock()

    assert corrected == first + timedelta(seconds=30)
    assert after == corrected + timedelta(seconds=2)
