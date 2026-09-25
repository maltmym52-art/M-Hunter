from dataclasses import dataclass, field

from m_hunter.analyzers.xss import XSSAnalysis, XSSContext
from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class XSSValidationResult:
    baseline: HttpResponse
    candidate: HttpResponse
    analysis: XSSAnalysis
    reflection_changed: bool
    context_changed: bool
    response_changed: bool
    execution_evidence: bool
    evidence: tuple[str, ...] = field(default_factory=tuple)

    @property
    def reflection_only(self) -> bool:
        return (
            self.analysis.reflected
            and not self.execution_evidence
            and not self.potential_xss
        )

    @property
    def potential_xss(self) -> bool:
        return (
            self.analysis.reflected
            and bool(self.analysis.contexts)
            and any(
                context in {
                    XSSContext.HTML_TEXT,
                    XSSContext.HTML_ATTRIBUTE,
                    XSSContext.JAVASCRIPT,
                    XSSContext.URL,
                    XSSContext.CSS,
                }
                for context in self.analysis.contexts
            )
        )

    @property
    def confirmed_execution(self) -> bool:
        return self.execution_evidence

    @property
    def status(self) -> str:
        if self.execution_evidence:
            return "execution_evidence"
        if self.potential_xss:
            return "potential_xss"
        if self.analysis.reflected:
            return "reflection_only"
        return "no_reflection"


class XSSValidator:
    """
    Validates controlled XSS reflection results.

    Reflection alone is not proof of XSS execution.
    Execution evidence must be explicitly supplied by an
    authorized validation layer.
    """

    def validate(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: XSSAnalysis,
        *,
        execution_evidence: bool = False,
    ) -> XSSValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, XSSAnalysis):
            raise TypeError("analysis must be an XSSAnalysis")

        evidence: list[str] = []

        reflection_changed = analysis.reflected
        context_changed = False

        if baseline.status_code != candidate.status_code:
            evidence.append(
                f"status code changed: "
                f"{baseline.status_code} -> {candidate.status_code}"
            )

        if baseline.content_length != candidate.content_length:
            evidence.append(
                f"content length changed: "
                f"{baseline.content_length} -> {candidate.content_length}"
            )

        if baseline.content != candidate.content:
            evidence.append("response content changed")

        response_changed = bool(evidence)

        if analysis.reflected:
            evidence.append(
                f"marker reflected {analysis.reflection_count} time(s)"
            )

        if analysis.contexts:
            context_names = ", ".join(
                context.value for context in analysis.contexts
            )
            evidence.append(f"reflection contexts: {context_names}")

        if execution_evidence:
            evidence.append(
                "explicit execution evidence supplied by validation layer"
            )

        return XSSValidationResult(
            baseline=baseline,
            candidate=candidate,
            analysis=analysis,
            reflection_changed=reflection_changed,
            context_changed=context_changed,
            response_changed=response_changed,
            execution_evidence=execution_evidence,
            evidence=tuple(evidence),
        )
