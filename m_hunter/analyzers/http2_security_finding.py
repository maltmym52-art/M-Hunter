from m_hunter.analyzers.http2_security import (
    HTTP2SecurityAnalysis,
    HTTP2SecurityIndicator,
    HTTP2SecurityIndicatorType,
)
from m_hunter.core.finding import Finding


class HTTP2SecurityFindingAnalyzer:
    name = "http2_security_finding"

    _METADATA = {
        HTTP2SecurityIndicatorType.HTTP2_SCHEME: (
            "HTTP/2 scheme detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.HTTP2_ALPN: (
            "HTTP/2 ALPN detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.HTTP2_PROTOCOL: (
            "HTTP/2 protocol detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.AUTHORITY_HEADER: (
            "HTTP/2 Authority Header Detected",
            "Info",
            "High",
            "CWE-20",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.PSEUDO_HEADER: (
            "HTTP/2 Pseudo-Header Detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.DUPLICATE_PSEUDO_HEADER: (
            "Duplicate HTTP/2 Pseudo-Header",
            "Medium",
            "High",
            "CWE-20",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.INVALID_PSEUDO_HEADER_ORDER: (
            "Invalid HTTP/2 Pseudo-Header Order",
            "Medium",
            "High",
            "CWE-20",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.HTTP2_ERROR: (
            "HTTP/2 Protocol Error",
            "Medium",
            "Medium",
            "CWE-400",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.STREAM_ERROR: (
            "HTTP/2 Stream Error",
            "Medium",
            "Medium",
            "CWE-400",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.GOAWAY_ERROR: (
            "HTTP/2 GOAWAY Error",
            "Medium",
            "Medium",
            "CWE-400",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.SETTINGS_EXPOSURE: (
            "HTTP/2 SETTINGS Information Exposed",
            "Low",
            "High",
            "CWE-200",
            "A05:2021",
        ),
        HTTP2SecurityIndicatorType.H2C_UPGRADE: (
            "Cleartext HTTP/2 h2c Upgrade Detected",
            "Medium",
            "High",
            "CWE-319",
            "A02:2021",
        ),
        HTTP2SecurityIndicatorType.PRIOR_KNOWLEDGE: (
            "HTTP/2 Prior-Knowledge Context Detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
    }

    def create_finding(
        self,
        indicator: HTTP2SecurityIndicator,
        target: str,
        endpoint: str | None = None,
    ) -> Finding:
        if not isinstance(indicator, HTTP2SecurityIndicator):
            raise TypeError("indicator must be HTTP2SecurityIndicator")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        if indicator.type not in self._METADATA:
            raise ValueError(
                f"unsupported HTTP/2 indicator type: {indicator.type}"
            )

        title, severity, confidence, cwe, owasp = self._METADATA[
            indicator.type
        ]

        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            target=target,
            endpoint=endpoint,
            description=(
                "An HTTP/2 security-relevant protocol indicator was "
                "detected during analysis."
            ),
            evidence=(
                f"{indicator.evidence} "
                f"Observed value: {indicator.value!r}"
            ),
            remediation=(
                "Review HTTP/2 configuration and protocol handling. "
                "Ensure HTTP/2 behavior is intentional, standards-compliant, "
                "and consistent across proxy and origin layers."
            ),
            cwe=cwe,
            owasp=owasp,
        )

    def create_findings(
        self,
        analysis: HTTP2SecurityAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, HTTP2SecurityAnalysis):
            raise TypeError(
                "analysis must be HTTP2SecurityAnalysis"
            )

        return [
            self.create_finding(
                indicator,
                target,
                endpoint,
            )
            for indicator in analysis.indicators
        ]
