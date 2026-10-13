
from collections import deque
from pathlib import Path
import time


class BehaviourDetector:
    """C1 detector using modification and extension-rename signals."""

    def __init__(self, window_seconds=2, file_threshold=10):
        self.window_seconds = window_seconds
        self.file_threshold = file_threshold
        self.events = deque()

    def analyze_event(self, event):
        now = time.monotonic()

        event_type = event.get("event_type", "unknown")
        src_path = event.get("src_path", "") or ""
        dest_path = event.get("dest_path", "") or ""

        # A modification is one signal for C1.
        is_modification = event_type == "modified"

        # A move is an extension-rename signal only if the
        # source and destination extensions differ.
        is_extension_rename = (
            event_type == "moved"
            and bool(src_path)
            and bool(dest_path)
            and Path(src_path).suffix.lower()
            != Path(dest_path).suffix.lower()
        )

        self.events.append(
            (now, is_modification, is_extension_rename)
        )

        # Keep only events from the rolling time window.
        while (
            self.events
            and now - self.events[0][0] > self.window_seconds
        ):
            self.events.popleft()

        modifications = sum(
            1 for _, modified, _ in self.events if modified
        )
        extension_renames = sum(
            1 for _, _, renamed in self.events if renamed
        )

        reasons = []

        if modifications:
            reasons.append(
                f"{modifications} file modifications "
                f"within {self.window_seconds}s"
            )

        if extension_renames:
            reasons.append(
                f"{extension_renames} extension-changing renames "
                f"within {self.window_seconds}s"
            )

        # C1 triggers only when BOTH signals reach the threshold.
        if (
            modifications >= self.file_threshold
            and extension_renames >= self.file_threshold
        ):
            reasons.append(
                "C1 triggered: both modification and "
                "extension-rename thresholds reached"
            )
            return 5, reasons

        return 0, reasons
