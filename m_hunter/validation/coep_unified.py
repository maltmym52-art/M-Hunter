from __future__ import annotations

from m_hunter.analyzers.coep import COEPAnalysis, COEPIndicatorType
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.analyzers.coep_finding import COEPFindingAnalyzer
from m_hunter.validation.analysis import (
    AnalysisValidation,
    FindingCandidate,
)


class COEPUnifiedValidator:
    """Adapt passive COEP analysis to the unified validation pipeline."""

    def validate(
        self,
        analysis: AnalysisResult,
        context: AnalysisContext,
    ) -> AnalysisValidation:
        decisions = self.validate_many(analysis, context)

        if not decisions:
            return AnalysisValidation.informational()

        return decisions[0]

    def validate_many(
        self,
        analysis: AnalysisResult,
        context: AnalysisContext,
    ) -> list[AnalysisValidation]:
        if not isinstance(analysis, AnalysisResult):
            raise TypeError(
                "analysis must be an instance of AnalysisResult"
            )

        if not isinstance(analysis.data, COEPAnalysis):
            raise TypeError(
                "analysis.data must be an instance of COEPAnalysis"
            )

        target = context.target
        target_value = (
            getattr(target, "url", None)
            or target
            or context.request_url
        )

        if not isinstance(target_value, str) or not target_value.strip():
            return [
                AnalysisValidation.invalid(
                    "COEP validation requires a valid target."
                )
            ]

        decisions: list[AnalysisValidation] = []

        for indicator in analysis.data.indicators:
            metadata = COEPFindingAnalyzer.METADATA.get(indicator.type)

            if metadata is None:
                continue

            (
                title,
                severity,
                confidence,
                cwe,
                owasp,
            ) = metadata

            if indicator.type == COEPIndicatorType.POLICY_MISSING:
                evidence = (
                    "Cross-Origin-Embedder-Policy header is missing"
                )
            elif indicator.value:
                evidence = (
                    f"{indicator.name}: {indicator.value}"
                )
            else:
                evidence = indicator.name

            description = (
                "COEP analysis detected the indicator "
                f"'{indicator.type.value}'. This indicator provides "
                "security context and does not by itself prove an "
                "exploitable vulnerability."
            )

            remediation = (
                "Configure Cross-Origin-Embedder-Policy according to "
                "the application's cross-origin isolation requirements. "
                "Use require-corp or credentialless where appropriate "
                "and verify compatibility with required cross-origin "
                "resources."
            )

            candidate = FindingCandidate(
                title=title,
                severity=severity,
                confidence=confidence,
                target=target_value,
                endpoint=context.request_url,
                description=description,
                evidence=evidence,
                remediation=remediation,
                cwe=cwe,
                owasp=owasp,
                metadata={
                    "analyzer": "coep",
                    "indicator_type": indicator.type.value,
                    "indicator_name": indicator.name,
                },
            )

            decisions.append(
                AnalysisValidation.finding(candidate)
            )

        if not decisions:
            return [
                AnalysisValidation.informational(
                    metadata={
                        "analyzer": "coep",
                        "reason": "no_supported_indicators",
                    }
                )
            ]

        return decisions
