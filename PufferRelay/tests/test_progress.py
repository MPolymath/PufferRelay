"""Progress/ETA tracker tests (issue #45)."""

from PufferRelay.utils.progress import ProgressTracker, format_duration


def test_format_duration():
    assert format_duration(None) == "--:--"
    assert format_duration(0) == "00:00"
    assert format_duration(6) == "00:06"
    assert format_duration(75) == "01:15"
    assert format_duration(3661) == "1:01:01"


def test_eta_uses_average_of_completed_steps():
    now = [0.0]
    tracker = ProgressTracker(4, clock=lambda: now[0])
    tracker.start()
    now[0] = 2.0
    tracker.step("ftp")
    now[0] = 6.0
    tracker.step("http")
    assert tracker.done == 2
    assert tracker.eta() == 6.0  # average 3s x 2 remaining
    line = tracker.status_line()
    assert "2/4" in line and "ETA 00:06" in line and "http" in line


def test_no_eta_before_first_step_and_zero_at_end():
    now = [10.0]
    tracker = ProgressTracker(2, clock=lambda: now[0])
    tracker.start()
    assert tracker.eta() is None
    now[0] = 12.0
    tracker.step("a")
    now[0] = 15.0
    tracker.step("b")
    assert tracker.eta() == 0.0
    assert "ETA 00:00" in tracker.status_line()
