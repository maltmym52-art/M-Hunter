from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.core.scan import Scan
from m_hunter.core.target import Target
from m_hunter.scanners.base import BaseScanner
from m_hunter.scanners.discovery import ScannerDiscovery
from m_hunter.scanners.registry import ScannerRegistry


class ScanEngine:
    def __init__(
        self,
        registry: ScannerRegistry | None = None,
        *,
        analyzer_registry: AnalyzerRegistry | None = None,
        auto_discover: bool = True,
    ):
        if registry is None:
            registry = ScannerRegistry()

            if auto_discover:
                ScannerDiscovery().register_all(registry)

        self.registry = registry
        self.analyzer_registry = (
            analyzer_registry
            if analyzer_registry is not None
            else AnalyzerRegistry()
        )

    def create_scan(self, target_url: str) -> Scan:
        target = Target(target_url)
        return Scan(target)

    def start_scan(self, target_url: str) -> Scan:
        scan = self.create_scan(target_url)
        scan.start()
        return scan

    def run_scanners(
        self,
        scan: Scan,
        scanners: list[BaseScanner],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for scanner in scanners:
            scanner_findings = scanner.run(scan.target)
            findings.extend(scanner_findings)

        return findings

    def run_registered_scanners(self, scan: Scan) -> list[Finding]:
        return self.run_scanners(
            scan,
            self.registry.get_all(),
        )

    def run_analyzers(
        self,
        response: HttpResponse,
    ) -> dict[str, dict]:
        results: dict[str, dict] = {}

        for analyzer in self.analyzer_registry.get_all():
            results[analyzer.name] = analyzer.analyze(response)

        return results

    def finish_scan(self, scan: Scan) -> None:
        scan.finish()
