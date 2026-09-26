from m_hunter.analyzers.clickjacking import (
    ClickjackingAnalysis,
    ClickjackingIndicatorType,
)
from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.core.finding import Finding


class ClickjackingFindingAnalyzer(FindingAnalyzer):
    name = "clickjacking_findings"
    description = "Converts clickjacking analysis into findings"

    METADATA = {
        ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS: (
            "Missing X-Frame-Options Protection",
            "Medium",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        ClickjackingIndicatorType.X_FRAME_OPTIONS_DENY: (
            "X-Frame-Options DENY",
            "Info",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        ClickjackingIndicatorType.X_FRAME_OPTIONS_SAMEORIGIN: (
            "X-Frame-Options SAMEORIGIN",
            "Info",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        ClickjackingIndicatorType.X_FRAME_OPTIONS_ALLOW_FROM: (
            "X-Frame-Options Uses ALLOW-FROM",
            "Low",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        ClickjackingIndicatorType.INVALID_X_FRAME_OPTIONS: (
            "Invalid X-Frame-Options Configuration",
            "Medium",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS: (
            "Missing CSP frame-ancestors Protection",
            "Low",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        ClickjackingIndicatorType.FRAME_ANCESTORS_NONE: (
            "CSP frame-ancestors none",
            "Info",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        ClickjackingIndicatorType.FRAME_ANCESTORS_SELF: (
            "CSP frame-ancestors self",
            "Info",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD: (
            "CSP frame-ancestors Allows Wildcard",
            "Medium",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        ClickjackingIndicatorType.FRAME_ANCESTORS_ORIGIN: (
            "CSP frame-ancestors Allows Explicit Origins",
            "Info",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        ClickjackingIndicatorType.CSP_PRESENT: (
            "Content-Security-Policy Present",
            "Info",
            "High",
            "CWE-693",
            "A05:2021",
        ),
    }

    def analyze(
        self,
        analysis: ClickjackingAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(
            analysis,
            ClickjackingAnalysis,
        ):
            raise TypeError(
                "analysis must be a ClickjackingAnalysis"
            )

        findings: list[Finding] = []

        for indicator in analysis.indicators:
            metadata = self.METADATA.get(indicator.type)

            if metadata is None:
                continue

            (
                title,
                severity,
                confidence,
                cwe,
                owasp,
            ) = metadata

            value_text = (
                f" Value: {indicator.value}."
                if indicator.value is not None
                else ""
            )

            if indicator.type in {
                ClickjackingIndicatorType.X_FRAME_OPTIONS_DENY,
                ClickjackingIndicatorType.X_FRAME_OPTIONS_SAMEORIGIN,
                ClickjackingIndicatorType.FRAME_ANCESTORS_NONE,
                ClickjackingIndicatorType.FRAME_ANCESTORS_SELF,
                ClickjackingIndicatorType.CSP_PRESENT,
            }:
                description = (
                    "The response contains a clickjacking-related "
                    "security control or configuration indicator."
                )
            else:
                description = (
                    "The response contains a clickjacking-related "
                    "configuration that may require review. "
                    "A header indicator alone does not prove that "
                    "an exploitable clickjacking condition exists."
                )

            remediation = (
                "Use X-Frame-Options with DENY or SAMEORIGIN, "
                "or define an appropriate CSP frame-ancestors policy. "
                "Review framing requirements for the application."
            )

            findings.append(
                self.create_finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=description,
                    evidence=(
                        f"Detected clickjacking indicator "
                        f"'{indicator.type.value}'."
                        f"{value_text}"
                    ),
                    remediation=remediation,
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings

    def analyze_response(
        self,
        response,
        *,
        target: str | None = None,
        endpoint: str | None = None,
    ) -> list[Finding]:
        from m_hunter.analyzers.clickjacking import (
            ClickjackingAnalyzer,
        )

        analysis = ClickjackingAnalyzer().analyze(response)

        return self.analyze(
            analysis,
            target=target or response.url,
            endpoint=endpoint or response.url,
        )
