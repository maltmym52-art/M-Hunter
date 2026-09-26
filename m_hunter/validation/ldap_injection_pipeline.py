from dataclasses import dataclass

from m_hunter.analyzers.ldap_injection import LDAPInjectionAnalysis
from m_hunter.analyzers.ldap_injection_finding import (
    LDAPInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.ldap_injection import (
    LDAPInjectionValidationResult,
    LDAPInjectionValidator,
)


@dataclass
class LDAPInjectionPipelineResult:
    validation: LDAPInjectionValidationResult
    accepted: bool
    findings: list[Finding]


class LDAPInjectionValidationPipeline:
    def __init__(
        self,
        validator=None,
        finding_analyzer=None,
    ):
        self.validator = validator or LDAPInjectionValidator()
        self.finding_analyzer = (
            finding_analyzer or LDAPInjectionFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: LDAPInjectionAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> LDAPInjectionPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, LDAPInjectionAnalysis):
            raise TypeError(
                "analysis must be a LDAPInjectionAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        if not isinstance(behavior_changed, bool):
            raise TypeError("behavior_changed must be a boolean")

        validation = self.validator.compare(
            baseline,
            candidate,
            analysis,
            behavior_changed=behavior_changed,
        )

        accepted = (
            analysis.detected
            and (
                validation.potential_ldap_injection
                or validation.behavior_changed
            )
        )

        findings = []

        if accepted:
            findings = self.finding_analyzer.analyze(
                analysis=analysis,
                target=target,
                endpoint=endpoint,
            )

        return LDAPInjectionPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
