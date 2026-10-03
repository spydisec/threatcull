# SPDX-License-Identifier: AGPL-3.0-only
"""How long each stage of a Fetch or Compile took, for the run history.

Stored in a Run's ``stats`` under ``timings`` as ``{stage: seconds}``, in the
order the stages ran, so a slow run shows where its time went.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager


class StageTimer:
    def __init__(self, clock: Callable[[], float] = time.perf_counter) -> None:
        self._clock = clock
        self._seconds: dict[str, float] = {}

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        """Time the block as ``name``; a stage entered twice adds up."""
        start = self._clock()
        try:
            yield
        finally:
            self._seconds[name] = self._seconds.get(name, 0.0) + self._clock() - start

    def to_json(self) -> dict[str, float]:
        return {name: round(seconds, 2) for name, seconds in self._seconds.items()}
