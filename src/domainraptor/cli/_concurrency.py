"""Concurrency helpers for CLI commands.

Lightweight `ThreadPoolExecutor` wrapper used to parallelise the per-host
enrichment loops in ``recon.py`` (Shodan/Censys/ZoomEye).  These loops
spend almost all their wall-clock time blocked on remote HTTP, so threads
give a near-linear speed-up while keeping the existing serial
post-processing semantics simple.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


def parallel_map(
    items: Iterable[T],
    fn: Callable[[T], R],
    *,
    max_workers: int = 5,
    timeout: float | None = None,
) -> list[tuple[T, R | None, BaseException | None]]:
    """Run ``fn`` over ``items`` in parallel and collect per-item results.

    Returns a list of ``(item, result, error)`` triples preserving no
    particular order.  Either ``result`` is set, or ``error`` is the
    exception raised for that item — never both.  Callers process the
    results sequentially afterwards, so list mutations stay race-free.

    ``timeout`` is applied to each individual ``Future.result`` call, not
    to the batch as a whole — slow items don't block fast ones.
    """
    items_list = list(items)
    if not items_list:
        return []

    workers = max(1, min(max_workers, len(items_list)))
    results: list[tuple[T, R | None, BaseException | None]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_item = {executor.submit(fn, item): item for item in items_list}
        for future in as_completed(future_to_item):
            item = future_to_item[future]
            try:
                value = future.result(timeout=timeout)
                results.append((item, value, None))
            except BaseException as exc:  # - propagated via tuple
                logger.debug("parallel_map: item %r failed: %s", item, exc, exc_info=True)
                results.append((item, None, exc))

    return results
