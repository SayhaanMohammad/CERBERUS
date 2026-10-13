
from datetime import datetime
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class MonitorHandler(FileSystemEventHandler):
    def __init__(self, callback, ignore_paths=None):
        super().__init__()
        self.callback = callback
        self.ignore_paths = [
            Path(p).resolve() for p in (ignore_paths or [])
        ]

    def _is_ignored(self, path):
        if not path:
            return False

        candidate = Path(path).resolve()

        for ignored in self.ignore_paths:
            try:
                candidate.relative_to(ignored)
                return True
            except ValueError:
                continue

        return False

    def on_any_event(self, event):
        if event.is_directory:
            return

        if event.event_type in ("opened", "closed"):
            return

        src_path = getattr(event, "src_path", "") or ""
        dest_path = getattr(event, "dest_path", "") or ""

        # Ignore events originating in or moving into ignored paths.
        if self._is_ignored(src_path) or self._is_ignored(dest_path):
            return

        record = {
            "event_type": event.event_type,
            "src_path": src_path,
            "dest_path": dest_path,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "is_directory": bool(event.is_directory),
        }

        self.callback(record)


def start_monitor(path, callback, ignore_paths=None):
    """Start watching a directory and return its Observer."""
    handler = MonitorHandler(callback, ignore_paths=ignore_paths)

    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()

    return observer
