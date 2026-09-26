from m_hunter.analyzers.open_redirect import (
    OpenRedirectAnalysis,
    OpenRedirectIndicatorType,
)
from m_hunter.core.finding import Finding


class OpenRedirectFindingAnalyzer:
    METADATA = {
        OpenRedirectIndicatorType.REDIRECT_PARAMETER: (
            "Redirect parameter detected",
            "Info",
            "High",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.URL_PARAMETER: (
            "URL parameter detected",
            "Info",
            "High",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.RETURN_URL_PARAMETER: (
            "Return URL parameter detected",
            "Info",
            "High",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.NEXT_PARAMETER: (
            "Next parameter detected",
            "Info",
            "High",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.CONTINUE_PARAMETER: (
            "Continue parameter detected",
            "Info",
            "High",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.DESTINATION_PARAMETER: (
            "Destination parameter detected",
            "Info",
            "High",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.EXTERNAL_URL: (
            "External redirect destination detected",
            "Medium",
            "Medium",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.ABSOLUTE_URL: (
            "Absolute redirect destination detected",
            "Medium",
            "Medium",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.PROTOCOL_RELATIVE_URL: (
            "Protocol-relative redirect destination detected",
            "Medium",
            "Medium",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.EXTERNAL_HOST: (
            "External redirect host detected",
            "High",
            "High",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.REDIRECT_RESPONSE: (
            "HTTP redirect response detected",
            "Info",
            "High",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.LOCATION_HEADER: (
            "Location header detected",
            "Info",
            "High",
            "CWE-601",
            "A07:2021",
        ),
        OpenRedirectIndicatorType.USER_CONTROLLED_DESTINATION: (
            "User-controlled redirect destination detected",
            "High",
            "Medium",
            "CWE-601",
            "A07:2021",
        ),
    }

    def analyze(
        self,
        analysis: OpenRedirectAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, OpenRedirectAnalysis):
            raise TypeError("analysis must be an OpenRedirectAnalysis")

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
                (
                    f"- {indicator.evidence}"
                    + (
                        f" Value: {indicator.value}"
                        if indicator.value is not None
                        else ""
                    )
                )
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
                        "An open-redirect-related indicator was detected. "
                        "The presence of a redirect parameter, external URL, "
                        "or redirect response alone does not prove an open "
                        "redirect vulnerability. Controlled validation is "
                        "required to determine whether an untrusted "
                        "destination is actually accepted and redirected to."
                    ),
                    evidence=evidence,
                    remediation=(
                        "Allow only trusted redirect destinations, prefer "
                        "server-side allowlists or opaque destination IDs, "
                        "validate destination hosts and schemes, reject "
                        "unexpected external destinations, and avoid using "
                        "unsanitized user-controlled URLs in redirect "
                        "responses."
                    ),
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
