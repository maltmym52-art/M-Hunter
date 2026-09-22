from m_hunter.core.engine import ScanEngine
from m_hunter.core.finding import Finding
from m_hunter.scanners.base import BaseScanner


class ScannerStub(BaseScanner):
    name = "test"
    description = "Test scanner"

    def __init__(self, findings=None):
        self.findings = findings or []
        self.received_target = None

    def run(self, target):
        self.received_target = target
        return self.findings


class EmptyScanner(BaseScanner):
    name = "empty"
    description = "Empty scanner"

    def run(self, target):
        return []


def create_finding(title="Test Finding"):
    return Finding(
        title=title,
        severity="Medium",
        confidence="High",
        target="https://example.com",
    )


def test_create_scan():
    engine = ScanEngine()

    scan = engine.create_scan("https://example.com")

    assert scan.target.url == "https://example.com"
    assert scan.status == "pending"
    assert scan.id


def test_start_scan():
    engine = ScanEngine()

    scan = engine.start_scan("https://example.com")

    assert scan.target.url == "https://example.com"
    assert scan.status == "running"
    assert scan.started_at is not None


def test_run_scanners():
    engine = ScanEngine()

    finding = create_finding()
    scanner = ScannerStub([finding])

    scan = engine.create_scan("https://example.com")

    findings = engine.run_scanners(scan, [scanner])

    assert findings == [finding]
    assert scanner.received_target is scan.target


def test_run_multiple_scanners():
    engine = ScanEngine()

    finding_one = create_finding("Finding One")
    finding_two = create_finding("Finding Two")

    scanner_one = ScannerStub([finding_one])
    scanner_two = ScannerStub([finding_two])

    scan = engine.create_scan("https://example.com")

    findings = engine.run_scanners(
        scan,
        [scanner_one, scanner_two],
    )

    assert findings == [finding_one, finding_two]


def test_run_scanner_with_no_findings():
    engine = ScanEngine()

    scanner = EmptyScanner()
    scan = engine.create_scan("https://example.com")

    findings = engine.run_scanners(scan, [scanner])

    assert findings == []


def test_run_scanners_with_empty_list():
    engine = ScanEngine()

    scan = engine.create_scan("https://example.com")

    findings = engine.run_scanners(scan, [])

    assert findings == []


def test_finish_scan():
    engine = ScanEngine()

    scan = engine.start_scan("https://example.com")

    engine.finish_scan(scan)

    assert scan.status == "completed"
    assert scan.finished_at is not None


def test_full_scan_lifecycle():
    engine = ScanEngine()

    finding = create_finding()
    scanner = ScannerStub([finding])

    scan = engine.start_scan("https://example.com")

    assert scan.status == "running"

    findings = engine.run_scanners(scan, [scanner])

    assert len(findings) == 1
    assert findings[0].title == "Test Finding"

    engine.finish_scan(scan)

    assert scan.status == "completed"
    assert scan.started_at is not None
    assert scan.finished_at is not None
