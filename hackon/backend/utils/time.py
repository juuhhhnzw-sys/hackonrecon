from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Timer:
    start: float

    @staticmethod
    def start_now() -> "Timer":
        return Timer(start=time.perf_counter())

    def elapsed_ms(self) -> int:
        return int((time.perf_counter() - self.start) * 1000)

