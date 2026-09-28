"""Application-level event delivery remains transport-neutral and isolated."""

from m_hunter.application import ApplicationService, ScanRequest
from m_hunter.events import (AssetDiscovered, ScanCompleted, ScanEventBus,
                             ScanStarted, StageStarted)


def test_application_publishes_lifecycle_events_and_ignores_listener_failures():
    bus = ScanEventBus()
    received = []
    bus.subscribe(lambda _event: (_ for _ in ()).throw(RuntimeError("UI failed")))
    bus.subscribe(received.append)
    result = ApplicationService(event_bus=bus).run(
        ScanRequest("https://example.test/", run_scanners=False)
    )
    assert result.state.value == "completed"
    assert any(isinstance(item, ScanStarted) for item in received)
    assert any(isinstance(item, AssetDiscovered) for item in received)
    assert any(isinstance(item, StageStarted) for item in received)
    assert any(isinstance(item, ScanCompleted) for item in received)
    assert all(not hasattr(item, "response") for item in received)
