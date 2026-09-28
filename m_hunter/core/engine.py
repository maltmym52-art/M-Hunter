from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.core.scan import Scan
from m_hunter.core.target import Target
from m_hunter.scanners.base import BaseScanner
from m_hunter.scanners.discovery import ScannerDiscovery
from m_hunter.scanners.registry import ScannerRegistry
from m_hunter.findings.converter import FindingProcessingResult
from m_hunter.validation.analysis_pipeline import (
    AnalysisFindingPipeline,
    AnalysisValidator,
)
from m_hunter.core.http import HttpEngine
from m_hunter.integrations.tools.runner import ToolRunner


class ScanEngine:
    def __init__(
        self,
        registry: ScannerRegistry | None = None,
        *,
        analyzer_registry: AnalyzerRegistry | None = None,
        finding_pipeline: AnalysisFindingPipeline | None = None,
        http_engine: HttpEngine | None = None,
        tool_runner: ToolRunner | None = None,
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
        self.finding_pipeline = finding_pipeline or AnalysisFindingPipeline()
        self.http_engine = http_engine
        self.tool_runner = tool_runner

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
    ) -> dict[str, object]:
        """Run analyzers while preserving the historical raw-data mapping."""
        context = AnalysisContext(response=response)
        return {
            name: result.data
            for name, result in self.run_analysis(context).items()
        }

    def run_analysis(
        self,
        context: AnalysisContext,
    ) -> dict[str, AnalysisResult]:
        """Run registered analyzers using the unified context interface."""
        if not isinstance(context, AnalysisContext):
            raise TypeError("context must be an AnalysisContext")

        results: dict[str, AnalysisResult] = {}

        for analyzer in self.analyzer_registry.get_all():
            results[analyzer.name] = analyzer.run(context)

        return results

    def validate_analysis(
        self,
        analysis: AnalysisResult,
        context: AnalysisContext,
        validator: AnalysisValidator,
    ) -> FindingProcessingResult:
        """Validate one analyzer result and convert an accepted issue.

        This focused entry point connects analysis, validation, and Findings
        without starting Recon, scanners, or a complete scan orchestration.
        """
        return self.finding_pipeline.process(
            analysis,
            context,
            validator,
        )

    def finish_scan(self, scan: Scan) -> None:
        scan.finish()
