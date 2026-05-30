"""Tests for cli._concurrency.parallel_map."""

from __future__ import annotations

import time

from domainraptor.cli._concurrency import parallel_map


def test_parallel_map_returns_results_for_each_item() -> None:
    results = parallel_map([1, 2, 3, 4], lambda x: x * 2, max_workers=2)
    assert len(results) == 4
    by_item = {item: (value, exc) for item, value, exc in results}
    assert by_item[1] == (2, None)
    assert by_item[4] == (8, None)


def test_parallel_map_captures_per_item_exceptions() -> None:
    def fn(x: int) -> int:
        if x == 2:
            raise ValueError("boom")
        return x

    results = parallel_map([1, 2, 3], fn, max_workers=2)
    assert len(results) == 3
    by_item = {item: (value, exc) for item, value, exc in results}
    assert by_item[1] == (1, None)
    assert by_item[3] == (3, None)
    assert by_item[2][0] is None
    assert isinstance(by_item[2][1], ValueError)


def test_parallel_map_handles_empty_input() -> None:
    assert parallel_map([], lambda x: x) == []


def test_parallel_map_is_faster_than_serial() -> None:
    def slow(x: int) -> int:
        time.sleep(0.05)
        return x

    start = time.monotonic()
    parallel_map(list(range(10)), slow, max_workers=10)
    elapsed = time.monotonic() - start
    # Serial would take ~0.5s; parallel with 10 workers should be well under 0.3s.
    assert elapsed < 0.3, f"parallel_map too slow: {elapsed:.2f}s"
