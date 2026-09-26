from dataclasses import dataclass

from m_hunter.analyzers.open_redirect import OpenRedirectAnalysis
from m_hunter.analyzers.open_redirect_finding import OpenRedirectFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.open_redirect import OpenRedirectValidationResult


@dataclass
class OpenRedirectPipelineResult:
    findings: list[Finding]
    validation: OpenRedirectValidationResult | None
    status: str


class OpenRedirectPipeline:
    def __init__(self):
        self.finding_analyzer = OpenRedirectFindingAnalyzer()

    def run(
        self,
        analysis: OpenRedirectAnalysis,
        target: str,
        endpoint: str | None = None,
        validation: OpenRedirectValidationResult | None = None,
    ) -> OpenRedirectPipelineResult:
        if not isinstance(analysis, OpenRedirectAnalysis):
            raise TypeError("analysis must be an OpenRedirectAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise TypeError("target must be a non-empty string")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        if validation is not None and not isinstance(
            validation, OpenRedirectValidationResult
        ):
            raise TypeError(
                "validation must be an OpenRedirectValidationResult or None"
            )

        findings = self.finding_analyzer.analyze(
            analysis=analysis,
            target=target,
            endpoint=endpoint,
        )

        if validation is not None:
            if validation.potential_open_redirect:
                status = "potential_open_redirect"
            elif validation.behavior_changed:
                status = "behavior_changed"
            elif validation.response_changed:
                status = "response_changed"
            elif findings:
                status = "findings"
            else:
                status = "no_findings"
        elif findings:
            status = "findings"
        else:
            status = "no_findings"

        return OpenRedirectPipelineResult(
            findings=findings,
            validation=validation,
            status=status,
        )
