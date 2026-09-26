from dataclasses import dataclass

from m_hunter.analyzers.command_injection import CommandInjectionAnalysis
from m_hunter.analyzers.command_injection_finding import (
    CommandInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.command_injection import (
    CommandInjectionValidationResult,
    CommandInjectionValidator,
)


@dataclass
class CommandInjectionPipelineResult:
    validation: CommandInjectionValidationResult
    accepted: bool
    findings: list[Finding]


class CommandInjectionValidationPipeline:
    def __init__(
        self,
        validator=None,
        finding_analyzer=None,
    ):
        self.validator = validator or CommandInjectionValidator()
        self.finding_analyzer = (
            finding_analyzer or CommandInjectionFindingAnalyzer()
        )

    def process(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: CommandInjectionAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        behavior_changed: bool = False,
    ) -> CommandInjectionPipelineResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, CommandInjectionAnalysis):
            raise TypeError(
                "analysis must be a CommandInjectionAnalysis"
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
                validation.potential_command_injection
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

        return CommandInjectionPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
