from dataclasses import dataclass, field
from typing import Any

from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.validation.finding import FindingValidator


@dataclass
class PipelineResult:
    findings: list[Finding] = field(default_factory=list)
    rejected: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def valid_count(self) -> int:
        return len(self.findings)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)


class FindingPipeline:
    """Converts analysis results into validated findings."""

    def __init__(
        self,
        finding_analyzer: FindingAnalyzer | None = None,
        validator: FindingValidator | None = None,
    ):
        self.finding_analyzer = (
            finding_analyzer
            if finding_analyzer is not None
            else FindingAnalyzer()
        )

        self.validator = (
            validator
            if validator is not None
            else FindingValidator()
        )

    def process(
        self,
        *,
        analysis: dict[str, Any],
        title: str,
        severity: str,
        confidence: str,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        cwe: str | None = None,
        owasp: str | None = None,
    ) -> PipelineResult:
        result = PipelineResult()

        finding = self.finding_analyzer.from_analysis(
            analysis=analysis,
            title=title,
            severity=severity,
            confidence=confidence,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cwe=cwe,
            owasp=owasp,
        )

        if finding is None:
            return result

        validation = self.validator.validate(finding)

        if validation.valid:
            result.findings.append(finding)
        else:
            result.rejected.append(finding)
            result.errors.extend(validation.errors)

        return result

    def process_many(
        self,
        analyses: list[dict[str, Any]],
        *,
        title: str,
        severity: str,
        confidence: str,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        cwe: str | None = None,
        owasp: str | None = None,
    ) -> PipelineResult:
        result = PipelineResult()

        for analysis in analyses:
            processed = self.process(
                analysis=analysis,
                title=title,
                severity=severity,
                confidence=confidence,
                target=target,
                endpoint=endpoint,
                parameter=parameter,
                description=description,
                evidence=evidence,
                remediation=remediation,
                cwe=cwe,
                owasp=owasp,
            )

            result.findings.extend(processed.findings)
            result.rejected.extend(processed.rejected)
            result.errors.extend(processed.errors)

        return result
