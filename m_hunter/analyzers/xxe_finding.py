from m_hunter.analyzers.xxe import (
    XXEAnalysis,
    XXEIndicatorType,
)
from m_hunter.core.finding import Finding


class XXEFindingAnalyzer:
    METADATA = {
        XXEIndicatorType.DOCTYPE_DECLARATION: (
            "Medium",
            "Medium",
            "XML DOCTYPE declaration detected; review whether external entity processing is enabled.",
        ),
        XXEIndicatorType.ENTITY_DECLARATION: (
            "Medium",
            "Medium",
            "XML entity declaration detected; entity processing should be reviewed for unsafe external resolution.",
        ),
        XXEIndicatorType.EXTERNAL_ENTITY: (
            "High",
            "Medium",
            "External XML entity declaration detected; this can be relevant to XXE if the parser resolves external entities.",
        ),
        XXEIndicatorType.SYSTEM_IDENTIFIER: (
            "High",
            "Medium",
            "XML SYSTEM identifier detected; external resource resolution should be reviewed.",
        ),
        XXEIndicatorType.PUBLIC_IDENTIFIER: (
            "High",
            "Medium",
            "XML PUBLIC identifier detected; external resource resolution should be reviewed.",
        ),
        XXEIndicatorType.ENTITY_REFERENCE: (
            "Low",
            "Low",
            "XML entity reference detected; entity usage alone does not establish an XXE vulnerability.",
        ),
    }

    REMEDIATION = (
        "Disable external entity resolution and DTD processing when not required. "
        "Use a securely configured XML parser and validate XML input according to the "
        "application's requirements."
    )

    def analyze(
        self,
        analysis: XXEAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, XXEAnalysis):
            raise TypeError("analysis must be an XXEAnalysis instance")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        findings: list[Finding] = []

        for indicator_type in analysis.types:
            metadata = self.METADATA.get(indicator_type)
            if metadata is None:
                continue

            severity, confidence, description = metadata
            indicators = [
                indicator
                for indicator in analysis.indicators
                if indicator.type == indicator_type
            ]

            evidence_lines = [
                f"Indicator type: {indicator_type.value}",
                f"Evidence count: {len(indicators)}",
            ]

            for indicator in indicators:
                evidence_lines.append(
                    f"Evidence: {indicator.evidence}"
                )

            finding = Finding(
                title=f"Potential XXE indicator: {indicator_type.value}",
                severity=severity,
                confidence=confidence,
                target=target,
                endpoint=endpoint,
                description=description,
                evidence="\n".join(evidence_lines),
                remediation=self.REMEDIATION,
                cwe="CWE-611",
                owasp="A05:2021",
            )

            findings.append(finding)

        return findings
