from m_hunter.analyzers.hpp import (
    HPPAnalysis,
    HPPIndicatorType,
)
from m_hunter.core.finding import Finding


class HPPFindingAnalyzer:
    METADATA = {
        HPPIndicatorType.DUPLICATE_PARAMETER: (
            "Duplicate HTTP parameter detected",
            "Low",
            "High",
            "CWE-235",
            "A04:2021",
        ),
        HPPIndicatorType.DUPLICATE_QUERY_PARAMETER: (
            "Duplicate query parameter detected",
            "Medium",
            "High",
            "CWE-235",
            "A04:2021",
        ),
        HPPIndicatorType.DUPLICATE_BODY_PARAMETER: (
            "Duplicate body parameter detected",
            "Medium",
            "High",
            "CWE-235",
            "A04:2021",
        ),
        HPPIndicatorType.PARAMETER_ARRAY: (
            "Parameter array detected",
            "Low",
            "High",
            "CWE-235",
            "A04:2021",
        ),
        HPPIndicatorType.CONFLICTING_VALUES: (
            "Conflicting parameter values detected",
            "Medium",
            "Medium",
            "CWE-235",
            "A04:2021",
        ),
        HPPIndicatorType.SAME_PARAMETER_DIFFERENT_VALUES: (
            "Same parameter has different values",
            "Medium",
            "Medium",
            "CWE-235",
            "A04:2021",
        ),
    }

    def analyze(
        self,
        analysis: HPPAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, HPPAnalysis):
            raise TypeError("analysis must be an HPPAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        findings: list[Finding] = []

        grouped = {}

        for indicator in analysis.indicators:
            grouped.setdefault(indicator.type, []).append(indicator)

        for indicator_type, indicators in grouped.items():
            metadata = self.METADATA.get(indicator_type)

            if metadata is None:
                continue

            title, severity, confidence, cwe, owasp = metadata

            evidence = "\n".join(
                f"- {indicator.evidence}"
                for indicator in indicators
            )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=(
                        "An HTTP parameter pollution-related indicator "
                        "was detected. Duplicate or conflicting parameters "
                        "do not by themselves prove a vulnerability because "
                        "application frameworks may intentionally support "
                        "multiple values. Controlled validation is required "
                        "to determine how different components interpret "
                        "the parameter."
                    ),
                    evidence=evidence,
                    remediation=(
                        "Define and enforce a single canonical parameter "
                        "interpretation, reject unexpected duplicate "
                        "parameters when appropriate, validate parameter "
                        "types and cardinality server-side, and ensure "
                        "upstream and downstream components use consistent "
                        "parameter parsing rules."
                    ),
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
