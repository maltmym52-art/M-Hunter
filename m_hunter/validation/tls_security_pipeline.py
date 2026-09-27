from m_hunter.analyzers.tls_security import TLSAnalysis
from m_hunter.analyzers.tls_security_finding import (
    TLSSecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.tls_security import (
    TLSValidationAnalyzer,
    TLSValidationResult,
)


class TLSSecurityPipeline:
    name = "tls_security_pipeline"

    def __init__(self):
        self.validator = TLSValidationAnalyzer()
        self.finding_analyzer = TLSSecurityFindingAnalyzer()

    def analyze(
        self,
        analysis: TLSAnalysis,
        target: str,
        *,
        endpoint: str | None = None,
        baseline_status: int | None = None,
        candidate_status: int | None = None,
        baseline_content: bytes | str | None = None,
        candidate_content: bytes | str | None = None,
        baseline_content_length: int | None = None,
        candidate_content_length: int | None = None,
        baseline_headers: dict[str, str] | None = None,
        candidate_headers: dict[str, str] | None = None,
    ) -> tuple[TLSValidationResult, list[Finding]]:
        if not isinstance(analysis, TLSAnalysis):
            raise TypeError("analysis must be a TLSAnalysis")

        validation = self.validator.validate(
            analysis,
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            baseline_content=baseline_content,
            candidate_content=candidate_content,
            baseline_content_length=baseline_content_length,
            candidate_content_length=candidate_content_length,
            baseline_headers=baseline_headers,
            candidate_headers=candidate_headers,
        )

        if not validation.potential_tls_security_issue:
            return validation, []

        findings = self.finding_analyzer.analyze(
            analysis,
            target=target,
            endpoint=endpoint,
        )

        return validation, findings

    def run(
        self,
        analysis: TLSAnalysis,
        target: str,
        **kwargs,
    ) -> tuple[TLSValidationResult, list[Finding]]:
        return self.analyze(
            analysis,
            target,
            **kwargs,
        )
