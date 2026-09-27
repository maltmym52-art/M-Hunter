from m_hunter.analyzers.http3_security import HTTP3Analysis
from m_hunter.analyzers.http3_security_finding import (
    HTTP3SecurityFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.http3_security import (
    HTTP3ValidationAnalyzer,
    HTTP3ValidationResult,
)


class HTTP3SecurityPipeline:
    name = "http3_security_pipeline"

    def __init__(self):
        self.validator = HTTP3ValidationAnalyzer()
        self.finding_analyzer = HTTP3SecurityFindingAnalyzer()

    def analyze(
        self,
        analysis: HTTP3Analysis,
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
    ) -> tuple[HTTP3ValidationResult, list[Finding]]:
        if not isinstance(analysis, HTTP3Analysis):
            raise TypeError("analysis must be an HTTP3Analysis")

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

        if not validation.potential_http3_security_issue:
            return validation, []

        findings = self.finding_analyzer.analyze(
            analysis,
            target=target,
            endpoint=endpoint,
        )

        return validation, findings

    def run(
        self,
        analysis: HTTP3Analysis,
        target: str,
        **kwargs,
    ) -> tuple[HTTP3ValidationResult, list[Finding]]:
        return self.analyze(
            analysis,
            target,
            **kwargs,
        )
