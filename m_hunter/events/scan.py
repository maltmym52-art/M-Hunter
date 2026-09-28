"""Small typed event contract independent of UI frameworks."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Callable


@dataclass(frozen=True)
class ScanEvent:
    """Base event carrying safe, presentation-neutral scan progress."""

    scan_id: str
    target: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    stage: str | None = None
    progress: float | None = None
    discovered_assets: int = 0
    findings_count: int = 0
    errors_count: int = 0
    message: str | None = None


class ScanStarted(ScanEvent):
    """A scan entered its running state."""


class StageStarted(ScanEvent):
    """A scan stage started."""


class StageUpdated(ScanEvent):
    """A scan stage or its counters changed."""


class AssetDiscovered(ScanEvent):
    """A scope-accepted asset was discovered."""


class RequestCompleted(ScanEvent):
    """An in-scope HTTP request completed."""


class FindingCreated(ScanEvent):
    """A validated canonical Finding was created."""


class ErrorOccurred(ScanEvent):
    """A scan component reported a recoverable or fatal issue."""


class ScanCompleted(ScanEvent):
    """A scan completed, possibly with partial errors."""


class ScanCancelled(ScanEvent):
    """A scan stopped at a safe application checkpoint."""


class ScanEventBus:
    """Synchronous event fan-out; observer exceptions never affect a scan."""

    def __init__(self) -> None:
        self._listeners: list[Callable[[ScanEvent], None]] = []
        self._lock = RLock()

    def subscribe(self, listener: Callable[[ScanEvent], None]) -> Callable[[], None]:
        """Subscribe and return an unsubscribe callback."""
        with self._lock:
            self._listeners.append(listener)

        def unsubscribe() -> None:
            with self._lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)
        return unsubscribe

    def publish(self, event: ScanEvent) -> None:
        """Notify a stable listener snapshot without propagating UI errors."""
        with self._lock:
            listeners = tuple(self._listeners)
        for listener in listeners:
            try:
                listener(event)
            except Exception:
                continue
