from dataclasses import dataclass

from m_hunter.analyzers.security_reporting import (
    SecurityReportingAnalysis,
    SecurityReportingIndicatorType,
)


@dataclass(frozen=True)
class SecurityReportingValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    security_indicator_present: bool
    invalid_reporting_configuration: bool
    potential_security_reporting_issue: bool
    status: str
    evidence: str


class SecurityReportingValidator:
    SECURITY_INDICATORS = {
        SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS,
        SecurityReportingIndicatorType.INVALID_REPORT_TO,
        SecurityReportingIndicatorType.MULTIPLE_REPORTING_ENDPOINTS,
        SecurityReportingIndicatorType.MULTIPLE_REPORT_TO,
    }

    def validate(
        self,
        analysis: SecurityReportingAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> SecurityReportingValidationResult:
        if not isinstance(analysis, SecurityReportingAnalysis):
            raise TypeError(
                "analysis must be an instance of SecurityReportingAnalysis"
            )

        if not isinstance(baseline_status, int):
            raise TypeError("baseline_status must be an integer")

        if not isinstance(candidate_status, int):
            raise TypeError("candidate_status must be an integer")

        for name, value in {
            "content_changed": content_changed,
            "content_length_changed": content_length_changed,
            "headers_changed": headers_changed,
        }.items():
            if not isinstance(value, bool):
                raise TypeError(f"{name} must be a boolean")

        status_changed = baseline_status != candidate_status

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        security_indicator_present = any(
            indicator.type in self.SECURITY_INDICATORS
            for indicator in analysis.indicators
        )

        invalid_reporting_configuration = (
            analysis.detected
            and security_indicator_present
        )

        potential = (
            invalid_reporting_configuration
            and response_changed
        )

        if potential:
            status = "potential"
        elif security_indicator_present:
            status = "indicator"
        elif analysis.detected:
            status = "detected"
        else:
            status = "clean"

        evidence_parts = [
            f"baseline_status={baseline_status}",
            f"candidate_status={candidate_status}",
            f"status_changed={status_changed}",
            f"content_changed={content_changed}",
            f"content_length_changed={content_length_changed}",
            f"headers_changed={headers_changed}",
            (
                "security_indicator_present="
                f"{security_indicator_present}"
            ),
        ]

        for indicator in analysis.indicators:
            if indicator.value:
                evidence_parts.append(
                    f"{indicator.type.value}={indicator.value}"
                )
            else:
                evidence_parts.append(indicator.type.value)

        return SecurityReportingValidationResult(
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            security_indicator_present=security_indicator_present,
            invalid_reporting_configuration=(
                invalid_reporting_configuration
            ),
            potential_security_reporting_issue=potential,
            status=status,
            evidence="; ".join(evidence_parts),
        )
