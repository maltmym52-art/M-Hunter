from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.adapters import LegacyAnalyzerAdapter
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.metadata import MetadataAnalyzer
from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.analyzers.coop import COOPAnalyzer
from m_hunter.core.response import HttpResponse
from m_hunter.core.engine import ScanEngine
from m_hunter.core.finding import Finding
from m_hunter.scanners.base import BaseScanner
from m_hunter.scanners.registry import ScannerRegistry


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


class SecondScanner(BaseScanner):
    name = "second"
    description = "Second test scanner"

    def __init__(self, findings=None):
        self.findings = findings or []
        self.received_target = None

    def run(self, target):
        self.received_target = target
        return self.findings


def create_finding(title="Test Finding"):
    return Finding(
        title=title,
        severity="Medium",
        confidence="High",
        target="https://example.com",
    )


def test_create_scan():
    engine = ScanEngine(auto_discover=False)

    scan = engine.create_scan("https://example.com")

    assert scan.target.url == "https://example.com"
    assert scan.status == "pending"
    assert scan.id


def test_start_scan():
    engine = ScanEngine(auto_discover=False)

    scan = engine.start_scan("https://example.com")

    assert scan.target.url == "https://example.com"
    assert scan.status == "running"
    assert scan.started_at is not None


def test_run_scanners():
    engine = ScanEngine(auto_discover=False)

    finding = create_finding()
    scanner = ScannerStub([finding])

    scan = engine.create_scan("https://example.com")

    findings = engine.run_scanners(scan, [scanner])

    assert findings == [finding]
    assert scanner.received_target is scan.target


def test_run_multiple_scanners():
    engine = ScanEngine(auto_discover=False)

    finding_one = create_finding("Finding One")
    finding_two = create_finding("Finding Two")

    scanner_one = ScannerStub([finding_one])
    scanner_two = SecondScanner([finding_two])

    scan = engine.create_scan("https://example.com")

    findings = engine.run_scanners(
        scan,
        [scanner_one, scanner_two],
    )

    assert findings == [finding_one, finding_two]
    assert scanner_one.received_target is scan.target
    assert scanner_two.received_target is scan.target


def test_run_scanner_with_no_findings():
    engine = ScanEngine(auto_discover=False)

    scanner = EmptyScanner()
    scan = engine.create_scan("https://example.com")

    findings = engine.run_scanners(scan, [scanner])

    assert findings == []


def test_run_scanners_with_empty_list():
    engine = ScanEngine(auto_discover=False)

    scan = engine.create_scan("https://example.com")

    findings = engine.run_scanners(scan, [])

    assert findings == []


def test_finish_scan():
    engine = ScanEngine(auto_discover=False)

    scan = engine.start_scan("https://example.com")

    engine.finish_scan(scan)

    assert scan.status == "completed"
    assert scan.finished_at is not None


def test_full_scan_lifecycle():
    engine = ScanEngine(auto_discover=False)

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


def test_engine_creates_default_registry():
    engine = ScanEngine(auto_discover=False)

    assert isinstance(engine.registry, ScannerRegistry)
    assert engine.registry.count() == 0


def test_engine_accepts_custom_registry():
    registry = ScannerRegistry()

    engine = ScanEngine(registry)

    assert engine.registry is registry


def test_registered_scanner_can_be_run():
    registry = ScannerRegistry()

    finding = create_finding()
    scanner = ScannerStub([finding])

    registry.register(scanner)

    engine = ScanEngine(registry)

    scan = engine.create_scan("https://example.com")

    findings = engine.run_registered_scanners(scan)

    assert findings == [finding]
    assert scanner.received_target is scan.target


def test_multiple_registered_scanners_can_be_run():
    registry = ScannerRegistry()

    finding_one = create_finding("Finding One")
    finding_two = create_finding("Finding Two")

    scanner_one = ScannerStub([finding_one])
    scanner_two = SecondScanner([finding_two])

    registry.register(scanner_one)
    registry.register(scanner_two)

    engine = ScanEngine(registry)

    scan = engine.create_scan("https://example.com")

    findings = engine.run_registered_scanners(scan)

    assert findings == [
        finding_one,
        finding_two,
    ]


def test_registered_scanners_with_no_findings():
    registry = ScannerRegistry()

    registry.register(EmptyScanner())

    engine = ScanEngine(registry)

    scan = engine.create_scan("https://example.com")

    findings = engine.run_registered_scanners(scan)

    assert findings == []


def test_run_registered_scanners_with_empty_registry():
    engine = ScanEngine(auto_discover=False)

    scan = engine.create_scan("https://example.com")

    findings = engine.run_registered_scanners(scan)

    assert findings == []


def test_registered_scanners_use_scan_target():
    registry = ScannerRegistry()

    scanner = ScannerStub()
    registry.register(scanner)

    engine = ScanEngine(registry)

    scan = engine.create_scan(
        "https://example.com/login"
    )

    engine.run_registered_scanners(scan)

    assert scanner.received_target is scan.target
    assert scanner.received_target.url == (
        "https://example.com/login"
    )


def test_engine_auto_discovers_scanners():
    engine = ScanEngine()

    assert engine.registry.count() >= 2
    assert "example" in engine.registry.names()
    assert "security_headers" in engine.registry.names()


def test_engine_auto_discovery_can_be_disabled():
    engine = ScanEngine(auto_discover=False)

    assert engine.registry.count() == 0


def test_custom_registry_is_not_auto_discovered():
    registry = ScannerRegistry()

    engine = ScanEngine(registry)

    assert engine.registry is registry
    assert engine.registry.count() == 0


def test_auto_discovered_scanners_can_run():
    engine = ScanEngine()

    scan = engine.create_scan("https://example.com")

    findings = engine.run_registered_scanners(scan)

    assert findings
    assert any(
        finding.target == "https://example.com"
        for finding in findings
    )


class CustomEngineAnalyzer(BaseAnalyzer):
    name = "custom"
    description = "Custom engine analyzer"

    def analyze(self, response: HttpResponse) -> dict:
        return {
            "status": response.status_code,
            "custom": True,
        }


class AnotherEngineAnalyzer(BaseAnalyzer):
    name = "another"
    description = "Another engine analyzer"

    def analyze(self, response: HttpResponse) -> dict:
        return {
            "another": True,
        }


def make_analyzer_response(
    status_code: int = 200,
) -> HttpResponse:
    return HttpResponse(
        status_code=status_code,
        url="https://example.com",
        headers={
            "Content-Type": "text/html",
        },
        content=b"<html>test</html>",
        cookies={},
        response_time=0.25,
        content_length=17,
    )


def test_scan_engine_creates_default_analyzer_registry():
    engine = ScanEngine(
        auto_discover=False,
    )

    assert isinstance(
        engine.analyzer_registry,
        AnalyzerRegistry,
    )

    assert engine.analyzer_registry.count() == 0


def test_scan_engine_accepts_custom_analyzer_registry():
    registry = AnalyzerRegistry()
    analyzer = MetadataAnalyzer()

    registry.register(analyzer)

    engine = ScanEngine(
        analyzer_registry=registry,
        auto_discover=False,
    )

    assert engine.analyzer_registry is registry
    assert engine.analyzer_registry.get("metadata") is analyzer


def test_run_analyzers_returns_empty_dict_when_registry_is_empty():
    engine = ScanEngine(
        auto_discover=False,
    )

    response = make_analyzer_response()

    results = engine.run_analyzers(response)

    assert results == {}


def test_run_analyzers_runs_registered_analyzer():
    registry = AnalyzerRegistry()
    analyzer = CustomEngineAnalyzer()

    registry.register(analyzer)

    engine = ScanEngine(
        analyzer_registry=registry,
        auto_discover=False,
    )

    response = make_analyzer_response(
        status_code=201,
    )

    results = engine.run_analyzers(response)

    assert results == {
        "custom": {
            "status": 201,
            "custom": True,
        }
    }


def test_run_analyzers_runs_multiple_analyzers():
    registry = AnalyzerRegistry()

    first = CustomEngineAnalyzer()
    second = AnotherEngineAnalyzer()

    registry.register(first)
    registry.register(second)

    engine = ScanEngine(
        analyzer_registry=registry,
        auto_discover=False,
    )

    response = make_analyzer_response()

    results = engine.run_analyzers(response)

    assert results == {
        "custom": {
            "status": 200,
            "custom": True,
        },
        "another": {
            "another": True,
        },
    }


def test_run_analyzers_uses_registered_analyzer_names():
    registry = AnalyzerRegistry()
    analyzer = CustomEngineAnalyzer()

    registry.register(analyzer)

    engine = ScanEngine(
        analyzer_registry=registry,
        auto_discover=False,
    )

    results = engine.run_analyzers(
        make_analyzer_response()
    )

    assert list(results.keys()) == ["custom"]


def test_run_analyzers_passes_same_response_to_analyzer():
    class IdentityAnalyzer(BaseAnalyzer):
        name = "identity"
        description = "Checks response identity"

        def analyze(self, response: HttpResponse) -> dict:
            return {
                "same_response": response.status_code == 404,
            }

    registry = AnalyzerRegistry()
    registry.register(IdentityAnalyzer())

    engine = ScanEngine(
        analyzer_registry=registry,
        auto_discover=False,
    )

    results = engine.run_analyzers(
        make_analyzer_response(status_code=404)
    )

    assert results["identity"]["same_response"] is True


def test_run_analyzers_with_metadata_analyzer():
    registry = AnalyzerRegistry()
    registry.register(MetadataAnalyzer())

    engine = ScanEngine(
        analyzer_registry=registry,
        auto_discover=False,
    )

    response = make_analyzer_response()

    results = engine.run_analyzers(response)

    assert "metadata" in results
    assert results["metadata"]["status_code"] == 200
    assert results["metadata"]["url"] == "https://example.com"
    assert results["metadata"]["is_html"] is True


def test_run_analysis_returns_unified_results_for_legacy_analyzers():
    registry = AnalyzerRegistry()
    analyzer = COOPAnalyzer()
    registry.register(LegacyAnalyzerAdapter(analyzer))
    engine = ScanEngine(
        analyzer_registry=registry,
        auto_discover=False,
    )

    results = engine.run_analysis(
        AnalysisContext(response=make_analyzer_response())
    )

    assert isinstance(results["coop"], AnalysisResult)
    assert results["coop"].analyzer_name == "coop"
    assert type(results["coop"].data).__name__ == "COOPAnalysis"


def test_run_analyzers_keeps_raw_adapter_data_for_compatibility():
    registry = AnalyzerRegistry()
    analyzer = COOPAnalyzer()
    registry.register(LegacyAnalyzerAdapter(analyzer))
    engine = ScanEngine(
        analyzer_registry=registry,
        auto_discover=False,
    )

    results = engine.run_analyzers(make_analyzer_response())

    assert type(results["coop"]).__name__ == "COOPAnalysis"


def test_scan_engine_scanner_registry_and_analyzer_registry_are_independent():
    engine = ScanEngine(
        auto_discover=False,
    )

    assert engine.registry.count() == 0
    assert engine.analyzer_registry.count() == 0
