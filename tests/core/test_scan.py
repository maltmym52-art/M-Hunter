from datetime import datetime

from m_hunter.core.scan import Scan
from m_hunter.core.target import Target


def test_scan_defaults():
    target = Target("https://example.com")

    scan = Scan(target)

    assert scan.target is target
    assert scan.id
    assert scan.status == "pending"
    assert scan.started_at is None
    assert scan.finished_at is None


def test_scan_id_is_unique():
    target = Target("https://example.com")

    scan_one = Scan(target)
    scan_two = Scan(target)

    assert scan_one.id != scan_two.id


def test_scan_start():
    target = Target("https://example.com")

    scan = Scan(target)
    scan.start()

    assert scan.status == "running"
    assert isinstance(scan.started_at, datetime)
    assert scan.finished_at is None


def test_scan_finish():
    target = Target("https://example.com")

    scan = Scan(target)
    scan.start()
    scan.finish()

    assert scan.status == "completed"
    assert isinstance(scan.started_at, datetime)
    assert isinstance(scan.finished_at, datetime)


def test_scan_finish_sets_completion_time():
    target = Target("https://example.com")

    scan = Scan(target)

    scan.finish()

    assert scan.status == "completed"
    assert scan.finished_at is not None


def test_scan_start_updates_status():
    target = Target("https://example.com")

    scan = Scan(target)

    assert scan.status == "pending"

    scan.start()

    assert scan.status == "running"


def test_scan_can_be_started_again():
    target = Target("https://example.com")

    scan = Scan(target)

    scan.start()
    first_start = scan.started_at

    scan.start()

    assert scan.status == "running"
    assert scan.started_at is not None
    assert scan.started_at >= first_start


def test_scan_can_be_finished_without_starting():
    target = Target("https://example.com")

    scan = Scan(target)

    scan.finish()

    assert scan.status == "completed"
    assert scan.started_at is None
    assert scan.finished_at is not None
