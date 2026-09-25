from m_hunter.analyzers.request_smuggling import (
    RequestSmugglingAnalysis,
    SmugglingIndicatorType,
)
from m_hunter.core.finding import Finding


class RequestSmugglingFindingAnalyzer:
    METADATA = {
        SmugglingIndicatorType.CONFLICTING_FRAMING: (
            "High",
            "Medium",
            "Conflicting HTTP message framing detected; "
            "this may be relevant to request smuggling when "
            "front-end and back-end parsers disagree.",
        ),
        SmugglingIndicatorType.DUPLICATE_CONTENT_LENGTH: (
            "High",
            "Medium",
            "Multiple Content-Length values detected; "
            "inconsistent message framing can be relevant "
            "to request smuggling.",
        ),
        SmugglingIndicatorType.AMBIGUOUS_TRANSFER_ENCODING: (
            "Medium",
            "Medium",
            "Ambiguous Transfer-Encoding configuration detected; "
            "parser differences may require further validation.",
        ),
    }

    REMEDIATION = (
        "Normalize HTTP message framing at trusted boundaries. "
        "Reject ambiguous or conflicting Content-Length and "
        "Transfer-Encoding headers, and ensure front-end and "
        "back-end components use consistent HTTP parsing rules."
    )

    def analyze(
        self,
        analysis: RequestSmugglingAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, RequestSmugglingAnalysis):
            raise TypeError(
                "analysis must be a RequestSmugglingAnalysis instance"
            )

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

                if indicator.smuggling_type is not None:
                    evidence_lines.append(
                        "Smuggling type: "
                        f"{indicator.smuggling_type.value}"
                    )

            findings.append(
                Finding(
                    title=(
                        "Potential HTTP request smuggling indicator: "
                        f"{indicator_type.value}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=description,
                    evidence="\n".join(evidence_lines),
                    remediation=self.REMEDIATION,
                    cwe="CWE-444",
                    owasp="A05:2021",
                )
            )

        return findings
