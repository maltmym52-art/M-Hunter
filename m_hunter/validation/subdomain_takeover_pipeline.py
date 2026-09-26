from dataclasses import dataclass

from m_hunter.analyzers.subdomain_takeover import SubdomainTakeoverAnalysis
from m_hunter.analyzers.subdomain_takeover_finding import (
    SubdomainTakeoverFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.validation.subdomain_takeover import (
    SubdomainTakeoverValidationResult,
    SubdomainTakeoverValidator,
)


@dataclass(frozen=True)
class SubdomainTakeoverPipelineResult:
    validation: SubdomainTakeoverValidationResult
    accepted: bool
    findings: list[Finding]


class SubdomainTakeoverPipeline:
    name = "subdomain_takeover_pipeline"

    def __init__(
        self,
        validator: SubdomainTakeoverValidator | None = None,
        finding_analyzer: SubdomainTakeoverFindingAnalyzer | None = None,
    ) -> None:
        self.validator = validator or SubdomainTakeoverValidator()
        self.finding_analyzer = (
            finding_analyzer or SubdomainTakeoverFindingAnalyzer()
        )

    def run(
        self,
        *,
        analysis: SubdomainTakeoverAnalysis,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
        dns_target_present: bool = False,
        response_changed: bool = False,
    ) -> SubdomainTakeoverPipelineResult:
        validation = self.validator.validate(
            analysis,
            dns_target_present=dns_target_present,
            response_changed=response_changed,
        )

        accepted = validation.potential_subdomain_takeover

        findings = (
            self.finding_analyzer.create_findings(
                analysis,
                target=target,
                endpoint=endpoint,
                parameter=parameter,
            )
            if accepted
            else []
        )

        return SubdomainTakeoverPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
