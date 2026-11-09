"""Progress and ETA tracking for multi-pass parsing (issue #45).

Each handler is one full tshark pass, so the average duration of the completed
passes is a good estimate for the remaining ones. The tracker is pure except
for its injectable clock, which makes it unit-testable.
"""

from __future__ import annotations

import time


def format_duration(seconds) -> str:
    """H:MM:SS or MM:SS; '--:--' when unknown."""
    if seconds is None:
        return "--:--"
    try:
        seconds = max(0, int(round(float(seconds))))
    except (TypeError, ValueError):
        return "--:--"
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


class ProgressTracker:
    """Track handler completions and estimate the remaining time."""

    def __init__(self, total_steps: int, clock=time.monotonic):
        self.total_steps = max(1, int(total_steps))
        self.clock = clock
        self.done = 0
        self.started = None
        self.last = None
        self.durations = []
        self.last_label = ""

    def start(self):
        self.started = self.clock()
        self.last = self.started
        self.done = 0
        self.durations = []

    def step(self, label: str = "") -> None:
        now = self.clock()
        if self.started is None:
            self.started = now
            self.last = now
        self.durations.append(max(0.0, now - self.last))
        self.last = now
        self.done = min(self.total_steps, self.done + 1)
        self.last_label = label

    def elapsed(self):
        if self.started is None:
            return 0.0
        return max(0.0, self.clock() - self.started)

    def eta(self):
        if self.done == 0 or self.done >= self.total_steps:
            return 0.0 if self.done >= self.total_steps else None
        average = sum(self.durations) / len(self.durations)
        return average * (self.total_steps - self.done)

    def status_line(self) -> str:
        label = f" {self.last_label}" if self.last_label else ""
        return (
            f"handler {self.done}/{self.total_steps}{label} | "
            f"elapsed {format_duration(self.elapsed())} | "
            f"ETA {format_duration(self.eta())}"
        )
