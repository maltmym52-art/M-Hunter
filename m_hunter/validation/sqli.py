from dataclasses import dataclass, field

from m_hunter.analyzers.sqli import SQLiAnalysis
from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class SQLiValidationResult:
    baseline: HttpResponse
    candidate: HttpResponse
    analysis: SQLiAnalysis
    error_indicator_changed: bool
    response_changed: bool
    status_changed: bool
    content_changed: bool
    potential_sqli: bool
    evidence: tuple[str, ...] = field(default_factory=tuple)

    @property
    def status(self) -> str:
        if self.potential_sqli:
            return "potential_sqli"

        if self.analysis.detected:
            return "error_indicator"

        return "no_indicator"


class SQLiValidator:
    """
    Validates controlled SQLi indicators by comparing baseline
    and candidate responses.

    Database errors and response differences are indicators only.
    They do not by themselves prove exploitable SQL injection.
    """

    def validate(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: SQLiAnalysis,
    ) -> SQLiValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, SQLiAnalysis):
            raise TypeError("analysis must be an SQLiAnalysis")

        evidence: list[str] = []

        status_changed = (
            baseline.status_code != candidate.status_code
        )

        content_changed = (
            baseline.content != candidate.content
        )

        response_changed = (
            status_changed
            or content_changed
            or baseline.content_length
            != candidate.content_length
        )

        if status_changed:
            evidence.append(
                f"status changed: "
                f"{baseline.status_code} -> "
                f"{candidate.status_code}"
            )

        if content_changed:
            evidence.append("response content changed")

        if (
            baseline.content_length
            != candidate.content_length
        ):
            evidence.append(
                f"content length changed: "
                f"{baseline.content_length} -> "
                f"{candidate.content_length}"
            )

        error_indicator_changed = analysis.detected

        if error_indicator_changed:
            evidence.append(
                f"SQL error indicators detected: "
                f"{analysis.indicator_count}"
            )

            for category in analysis.categories:
                evidence.append(
                    f"database category: {category}"
                )

        potential_sqli = (
            analysis.detected
            and response_changed
        )

        if potential_sqli:
            evidence.append(
                "database error indicators and response "
                "behavior changed together"
            )

        return SQLiValidationResult(
            baseline=baseline,
            candidate=candidate,
            analysis=analysis,
            error_indicator_changed=error_indicator_changed,
            response_changed=response_changed,
            status_changed=status_changed,
            content_changed=content_changed,
            potential_sqli=potential_sqli,
            evidence=tuple(evidence),
        )
