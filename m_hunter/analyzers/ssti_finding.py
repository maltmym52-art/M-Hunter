from collections import defaultdict

from m_hunter.analyzers.ssti import (
    SSTIAnalysis,
    SSTIEngine,
    SSTIIndicatorType,
)
from m_hunter.core.finding import Finding


class SSTIFindingAnalyzer:
    """
    Convert SSTI analysis indicators into structured findings.

    Template syntax, reflection, and engine markers are indicators
    for further validation. They do not by themselves confirm
    server-side template evaluation or code execution.
    """

    METADATA = {
        SSTIIndicatorType.TEMPLATE_SYNTAX: (
            "Medium",
            "Medium",
        ),
        SSTIIndicatorType.EXPRESSION_REFLECTION: (
            "Medium",
            "Medium",
        ),
        SSTIIndicatorType.ENGINE_MARKER: (
            "Low",
            "Low",
        ),
    }

    ENGINE_NAMES = {
        SSTIEngine.JINJA2: "Jinja2",
        SSTIEngine.TWIG: "Twig",
        SSTIEngine.DJANGO: "Django",
        SSTIEngine.FREEMARKER: "FreeMarker",
        SSTIEngine.VELOCITY: "Velocity",
        SSTIEngine.THYMELEAF: "Thymeleaf",
        SSTIEngine.ERB: "ERB",
        SSTIEngine.UNKNOWN: "Unknown",
    }

    def analyze(
        self,
        analysis: SSTIAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, SSTIAnalysis):
            raise TypeError("analysis must be an SSTIAnalysis instance")

        findings: list[Finding] = []

        grouped = defaultdict(list)

        for indicator in analysis.indicators:
            grouped[indicator.type].append(indicator)

        for indicator_type, indicators in grouped.items():
            severity, confidence = self.METADATA.get(
                indicator_type,
                ("Low", "Low"),
            )

            if indicator_type == SSTIIndicatorType.TEMPLATE_SYNTAX:
                title = "Potential server-side template injection indicator"
                description = (
                    "Template syntax was observed in the analyzed "
                    "content. This may indicate template processing "
                    "or reflected template-like input, but it does "
                    "not confirm server-side evaluation."
                )
                remediation = (
                    "Avoid evaluating user-controlled template syntax. "
                    "Use safe rendering APIs, strict template contexts, "
                    "and appropriate input handling."
                )

            elif indicator_type == SSTIIndicatorType.EXPRESSION_REFLECTION:
                title = "Potential SSTI expression reflection"
                description = (
                    "A supplied marker was reflected in the analyzed "
                    "content. Reflection alone does not demonstrate "
                    "server-side template evaluation."
                )
                remediation = (
                    "Ensure user-controlled input is treated strictly "
                    "as data and cannot become executable template "
                    "syntax."
                )

            else:
                title = "Template engine marker detected"
                description = (
                    "A template engine marker was observed in the "
                    "analyzed content. This provides technology "
                    "context but does not confirm SSTI."
                )
                remediation = (
                    "Review template engine configuration and ensure "
                    "untrusted input cannot reach template evaluation "
                    "contexts."
                )

            evidence_lines = [
                f"Indicator: {indicator_type.value}",
                f"Target: {target}",
                f"Endpoint: {endpoint or 'unknown'}",
                f"Evidence count: {len(indicators)}",
            ]

            for indicator in indicators:
                engine = self.ENGINE_NAMES.get(
                    indicator.engine,
                    indicator.engine.value,
                )
                evidence_lines.append(
                    f"- Evidence: {indicator.evidence} | "
                    f"Engine: {engine} | "
                    f"Position: {indicator.position}"
                )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=description,
                    evidence="\n".join(evidence_lines),
                    remediation=remediation,
                    cwe="CWE-1336",
                    owasp="A03:2021",
                )
            )

        return findings
