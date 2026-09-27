from m_hunter.analyzers.http3_security import (
    HTTP3Analysis,
    HTTP3IndicatorType,
)
from m_hunter.core.finding import Finding


class HTTP3SecurityFindingAnalyzer:
    name = "http3_security_finding"

    FINDING_METADATA = {
        HTTP3IndicatorType.QUIC_ERROR: (
            "QUIC error detected",
            "Medium",
            "Medium",
            "CWE-400",
            "A05:2021",
        ),
        HTTP3IndicatorType.HTTP3_ERROR: (
            "HTTP/3 error detected",
            "Medium",
            "Medium",
            "CWE-400",
            "A05:2021",
        ),
        HTTP3IndicatorType.DOWNGRADE_INDICATOR: (
            "HTTP/3 downgrade indicator detected",
            "Medium",
            "Medium",
            "CWE-757",
            "A07:2021",
        ),
        HTTP3IndicatorType.FALLBACK_INDICATOR: (
            "HTTP/3 fallback indicator detected",
            "Low",
            "Medium",
            "CWE-757",
            "A07:2021",
        ),
        HTTP3IndicatorType.MALFORMED_PROTOCOL: (
            "Malformed HTTP/3 protocol indicator detected",
            "Medium",
            "Medium",
            "CWE-20",
            "A05:2021",
        ),
        HTTP3IndicatorType.HTTP3_SCHEME: (
            "HTTP/3 scheme detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HTTP3IndicatorType.HTTP3_ALPN: (
            "HTTP/3 ALPN detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HTTP3IndicatorType.HTTP3_PROTOCOL: (
            "HTTP/3 protocol detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HTTP3IndicatorType.QUIC_PROTOCOL: (
            "QUIC protocol detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HTTP3IndicatorType.ALT_SVC_H3: (
            "Alt-Svc advertises HTTP/3",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HTTP3IndicatorType.AUTHORITY_CONTEXT: (
            "HTTP/3 authority context detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        HTTP3IndicatorType.PSEUDO_HEADER: (
            "HTTP/3 pseudo-header detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
    }

    DESCRIPTIONS = {
        HTTP3IndicatorType.QUIC_ERROR:
            "A QUIC error was observed during HTTP/3 communication.",
        HTTP3IndicatorType.HTTP3_ERROR:
            "An HTTP/3 protocol error was observed.",
        HTTP3IndicatorType.DOWNGRADE_INDICATOR:
            "The observed communication contains an indicator that HTTP/3 was downgraded.",
        HTTP3IndicatorType.FALLBACK_INDICATOR:
            "The observed communication contains an HTTP/3 fallback indicator.",
        HTTP3IndicatorType.MALFORMED_PROTOCOL:
            "A malformed HTTP/3 protocol indicator was observed.",
        HTTP3IndicatorType.HTTP3_SCHEME:
            "HTTP/3 was identified through the supplied scheme.",
        HTTP3IndicatorType.HTTP3_ALPN:
            "An HTTP/3 ALPN identifier was observed.",
        HTTP3IndicatorType.HTTP3_PROTOCOL:
            "HTTP/3 protocol information was observed.",
        HTTP3IndicatorType.QUIC_PROTOCOL:
            "QUIC protocol information was observed.",
        HTTP3IndicatorType.ALT_SVC_H3:
            "The endpoint advertises HTTP/3 through Alt-Svc.",
        HTTP3IndicatorType.AUTHORITY_CONTEXT:
            "An HTTP/3 authority context was observed.",
        HTTP3IndicatorType.PSEUDO_HEADER:
            "An HTTP/3 pseudo-header was observed.",
    }

    REMEDIATION = {
        HTTP3IndicatorType.QUIC_ERROR:
            "Review QUIC error handling, protocol compatibility, and server-side configuration.",
        HTTP3IndicatorType.HTTP3_ERROR:
            "Review HTTP/3 protocol handling and server implementation errors.",
        HTTP3IndicatorType.DOWNGRADE_INDICATOR:
            "Review protocol negotiation and ensure downgrade behavior is intentional and secure.",
        HTTP3IndicatorType.FALLBACK_INDICATOR:
            "Review HTTP/3 fallback behavior and ensure fallback protocols maintain equivalent security controls.",
        HTTP3IndicatorType.MALFORMED_PROTOCOL:
            "Review HTTP/3 input validation and protocol parsing behavior.",
        HTTP3IndicatorType.HTTP3_SCHEME:
            "Maintain a secure HTTP/3 configuration and modern TLS deployment.",
        HTTP3IndicatorType.HTTP3_ALPN:
            "Maintain correct ALPN negotiation for supported HTTP/3 deployments.",
        HTTP3IndicatorType.HTTP3_PROTOCOL:
            "Maintain a correctly configured HTTP/3 implementation.",
        HTTP3IndicatorType.QUIC_PROTOCOL:
            "Maintain a secure QUIC configuration.",
        HTTP3IndicatorType.ALT_SVC_H3:
            "Ensure advertised HTTP/3 endpoints are correctly configured and secured.",
        HTTP3IndicatorType.AUTHORITY_CONTEXT:
            "Validate authority handling and routing consistently across HTTP/3 requests.",
        HTTP3IndicatorType.PSEUDO_HEADER:
            "Validate HTTP/3 pseudo-header parsing and ordering according to the protocol.",
    }

    def analyze(
        self,
        analysis: HTTP3Analysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, HTTP3Analysis):
            raise TypeError("analysis must be an HTTP3Analysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        findings: list[Finding] = []

        for indicator in analysis.indicators:
            metadata = self.FINDING_METADATA.get(indicator.type)

            if metadata is None:
                continue

            (
                title,
                severity,
                confidence,
                cwe,
                owasp,
            ) = metadata

            value = (
                f" Value: {indicator.value}."
                if indicator.value is not None
                else ""
            )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=(
                        self.DESCRIPTIONS[indicator.type]
                        + value
                    ),
                    evidence=f"{indicator.name}.{value}",
                    remediation=self.REMEDIATION[
                        indicator.type
                    ],
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings

    def create_findings(
        self,
        analysis: HTTP3Analysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        return self.analyze(
            analysis=analysis,
            target=target,
            endpoint=endpoint,
        )
