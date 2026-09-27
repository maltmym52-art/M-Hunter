from m_hunter.analyzers.tls_security import (
    TLSAnalysis,
    TLSIndicator,
    TLSIndicatorType,
)
from m_hunter.core.finding import Finding


class TLSSecurityFindingAnalyzer:
    name = "tls_security_finding"

    FINDING_METADATA = {
        TLSIndicatorType.SSLV2: (
            "SSLv2 is supported",
            "Critical",
            "High",
            "CWE-326",
            "A02:2021",
        ),
        TLSIndicatorType.SSLV3: (
            "SSLv3 is supported",
            "High",
            "High",
            "CWE-326",
            "A02:2021",
        ),
        TLSIndicatorType.TLS10: (
            "TLS 1.0 is supported",
            "Medium",
            "High",
            "CWE-326",
            "A02:2021",
        ),
        TLSIndicatorType.TLS11: (
            "TLS 1.1 is supported",
            "Medium",
            "High",
            "CWE-326",
            "A02:2021",
        ),
        TLSIndicatorType.EXPIRED_CERTIFICATE: (
            "TLS certificate is expired",
            "High",
            "High",
            "CWE-295",
            "A07:2021",
        ),
        TLSIndicatorType.SELF_SIGNED_CERTIFICATE: (
            "TLS certificate is self-signed",
            "Medium",
            "High",
            "CWE-295",
            "A07:2021",
        ),
        TLSIndicatorType.HOSTNAME_MISMATCH: (
            "TLS certificate hostname mismatch",
            "High",
            "High",
            "CWE-297",
            "A07:2021",
        ),
        TLSIndicatorType.INVALID_CERTIFICATE_CHAIN: (
            "TLS certificate chain is invalid",
            "High",
            "High",
            "CWE-295",
            "A07:2021",
        ),
        TLSIndicatorType.WEAK_CIPHER: (
            "Weak TLS cipher detected",
            "High",
            "High",
            "CWE-327",
            "A02:2021",
        ),
        TLSIndicatorType.WEAK_KEY_EXCHANGE: (
            "Weak TLS key exchange detected",
            "High",
            "High",
            "CWE-326",
            "A02:2021",
        ),
        TLSIndicatorType.WEAK_SIGNATURE: (
            "Weak certificate signature algorithm detected",
            "Medium",
            "High",
            "CWE-327",
            "A02:2021",
        ),
        TLSIndicatorType.HSTS_PRESENT: (
            "HTTP Strict Transport Security is enabled",
            "Info",
            "High",
            "CWE-319",
            "A02:2021",
        ),
        TLSIndicatorType.CERTIFICATE_PRESENT: (
            "TLS certificate is present",
            "Info",
            "High",
            "CWE-295",
            "A07:2021",
        ),
        TLSIndicatorType.CERTIFICATE_TRANSPARENCY: (
            "Certificate Transparency information is present",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        TLSIndicatorType.TLS_PRESENT: (
            "TLS is in use",
            "Info",
            "High",
            "CWE-319",
            "A02:2021",
        ),
        TLSIndicatorType.TLS_VERSION: (
            "TLS protocol version detected",
            "Info",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        TLSIndicatorType.TLS12: (
            "TLS 1.2 is supported",
            "Info",
            "High",
            "CWE-326",
            "A02:2021",
        ),
        TLSIndicatorType.TLS13: (
            "TLS 1.3 is supported",
            "Info",
            "High",
            "CWE-326",
            "A02:2021",
        ),
    }

    DESCRIPTIONS = {
        TLSIndicatorType.SSLV2:
            "The endpoint supports the obsolete SSLv2 protocol.",
        TLSIndicatorType.SSLV3:
            "The endpoint supports the obsolete SSLv3 protocol.",
        TLSIndicatorType.TLS10:
            "The endpoint supports TLS 1.0, an obsolete protocol version.",
        TLSIndicatorType.TLS11:
            "The endpoint supports TLS 1.1, an obsolete protocol version.",
        TLSIndicatorType.EXPIRED_CERTIFICATE:
            "The TLS certificate has expired and can no longer provide current validity assurance.",
        TLSIndicatorType.SELF_SIGNED_CERTIFICATE:
            "The TLS certificate is self-signed and is not anchored in a trusted public certificate authority.",
        TLSIndicatorType.HOSTNAME_MISMATCH:
            "The certificate identity does not match the requested hostname.",
        TLSIndicatorType.INVALID_CERTIFICATE_CHAIN:
            "The TLS certificate chain could not be validated successfully.",
        TLSIndicatorType.WEAK_CIPHER:
            "The endpoint exposes a TLS cipher associated with obsolete or weak cryptographic protection.",
        TLSIndicatorType.WEAK_KEY_EXCHANGE:
            "The endpoint exposes a weak or anonymous key-exchange configuration.",
        TLSIndicatorType.WEAK_SIGNATURE:
            "The certificate uses a weak signature algorithm.",
        TLSIndicatorType.HSTS_PRESENT:
            "The endpoint advertises HTTP Strict Transport Security.",
        TLSIndicatorType.CERTIFICATE_PRESENT:
            "A TLS certificate was observed for the endpoint.",
        TLSIndicatorType.CERTIFICATE_TRANSPARENCY:
            "Certificate Transparency information was observed.",
        TLSIndicatorType.TLS_PRESENT:
            "TLS was observed on the endpoint.",
        TLSIndicatorType.TLS_VERSION:
            "A TLS protocol version was observed.",
        TLSIndicatorType.TLS12:
            "The endpoint supports TLS 1.2.",
        TLSIndicatorType.TLS13:
            "The endpoint supports TLS 1.3.",
    }

    REMEDIATION = {
        TLSIndicatorType.SSLV2:
            "Disable SSLv2 and require a modern TLS configuration.",
        TLSIndicatorType.SSLV3:
            "Disable SSLv3 and require a modern TLS configuration.",
        TLSIndicatorType.TLS10:
            "Disable TLS 1.0 and use TLS 1.2 or TLS 1.3.",
        TLSIndicatorType.TLS11:
            "Disable TLS 1.1 and use TLS 1.2 or TLS 1.3.",
        TLSIndicatorType.EXPIRED_CERTIFICATE:
            "Replace the expired certificate with a currently valid certificate.",
        TLSIndicatorType.SELF_SIGNED_CERTIFICATE:
            "Use a certificate issued by a trusted certificate authority where public trust is required.",
        TLSIndicatorType.HOSTNAME_MISMATCH:
            "Install a certificate whose identity matches the requested hostname.",
        TLSIndicatorType.INVALID_CERTIFICATE_CHAIN:
            "Correct the certificate chain and ensure required intermediate certificates are served.",
        TLSIndicatorType.WEAK_CIPHER:
            "Disable obsolete and weak cipher suites and prefer modern authenticated encryption.",
        TLSIndicatorType.WEAK_KEY_EXCHANGE:
            "Disable anonymous or weak key-exchange configurations and use modern authenticated key exchange.",
        TLSIndicatorType.WEAK_SIGNATURE:
            "Replace certificates using weak signature algorithms with certificates using modern algorithms.",
        TLSIndicatorType.HSTS_PRESENT:
            "Maintain HSTS with an appropriate max-age and deployment policy.",
        TLSIndicatorType.CERTIFICATE_PRESENT:
            "Maintain a valid certificate configuration.",
        TLSIndicatorType.CERTIFICATE_TRANSPARENCY:
            "Maintain appropriate Certificate Transparency coverage for publicly trusted certificates.",
        TLSIndicatorType.TLS_PRESENT:
            "Use modern TLS versions and secure cipher suites.",
        TLSIndicatorType.TLS_VERSION:
            "Prefer TLS 1.2 or TLS 1.3 and disable obsolete protocol versions.",
        TLSIndicatorType.TLS12:
            "Maintain TLS 1.2 support with modern cipher suites.",
        TLSIndicatorType.TLS13:
            "Maintain TLS 1.3 support.",
    }

    def analyze(
        self,
        analysis: TLSAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, TLSAnalysis):
            raise TypeError("analysis must be a TLSAnalysis")

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

            evidence = (
                f"{indicator.name}.{value}"
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
                    evidence=evidence,
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
        analysis: TLSAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        return self.analyze(
            analysis=analysis,
            target=target,
            endpoint=endpoint,
        )
