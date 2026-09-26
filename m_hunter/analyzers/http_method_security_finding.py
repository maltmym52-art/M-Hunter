from m_hunter.analyzers.http_method_security import (
    HTTPMethodSecurityAnalysis,
    HTTPMethodSecurityIndicatorType,
)
from m_hunter.core.finding import Finding


class HTTPMethodSecurityFindingAnalyzer:
    METADATA = {
        HTTPMethodSecurityIndicatorType.DANGEROUS_METHOD: (
            "Potentially dangerous HTTP method detected",
            "Low",
            "Medium",
            "CWE-749",
            "OWASP A05:2021",
        ),
        HTTPMethodSecurityIndicatorType.TRACE_ENABLED: (
            "HTTP TRACE method appears enabled",
            "Medium",
            "High",
            "CWE-693",
            "OWASP A05:2021",
        ),
        HTTPMethodSecurityIndicatorType.TRACK_ENABLED: (
            "HTTP TRACK method appears enabled",
            "Medium",
            "High",
            "CWE-693",
            "OWASP A05:2021",
        ),
        HTTPMethodSecurityIndicatorType.CONNECT_ENABLED: (
            "HTTP CONNECT method appears enabled",
            "Medium",
            "High",
            "CWE-441",
            "OWASP A10:2021",
        ),
        HTTPMethodSecurityIndicatorType.UNEXPECTED_PUT: (
            "PUT HTTP method detected",
            "Info",
            "High",
            None,
            "OWASP A05:2021",
        ),
        HTTPMethodSecurityIndicatorType.UNEXPECTED_DELETE: (
            "DELETE HTTP method detected",
            "Info",
            "High",
            None,
            "OWASP A05:2021",
        ),
        HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_HEADER: (
            "HTTP method override header detected",
            "Low",
            "Medium",
            "CWE-436",
            "OWASP A05:2021",
        ),
        HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_PARAMETER: (
            "HTTP method override parameter detected",
            "Low",
            "Medium",
            "CWE-436",
            "OWASP A05:2021",
        ),
        HTTPMethodSecurityIndicatorType.OPTIONS_EXPOSURE: (
            "HTTP OPTIONS method detected",
            "Info",
            "High",
            None,
            "OWASP A05:2021",
        ),
        HTTPMethodSecurityIndicatorType.ALLOW_HEADER: (
            "HTTP Allow header detected",
            "Info",
            "High",
            None,
            "OWASP A05:2021",
        ),
        HTTPMethodSecurityIndicatorType.METHOD_NOT_ALLOWED: (
            "HTTP method was rejected with 405",
            "Info",
            "High",
            None,
            "OWASP A05:2021",
        ),
        HTTPMethodSecurityIndicatorType.METHOD_INCONSISTENCY: (
            "HTTP method handling inconsistency detected",
            "Medium",
            "Medium",
            "CWE-436",
            "OWASP A05:2021",
        ),
    }

    REMEDIATION = (
        "Restrict HTTP methods to those required by the application, "
        "disable unnecessary TRACE, TRACK, and CONNECT handling, "
        "review method override mechanisms, enforce authorization "
        "consistently across methods, and verify that rejected methods "
        "are handled consistently."
    )

    def analyze(
        self,
        *,
        analysis: HTTPMethodSecurityAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(
            analysis,
            HTTPMethodSecurityAnalysis,
        ):
            raise TypeError(
                "analysis must be an HTTPMethodSecurityAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError(
                "target must be a non-empty string"
            )

        if endpoint is not None and not isinstance(
            endpoint,
            str,
        ):
            raise TypeError(
                "endpoint must be a string or None"
            )

        findings: list[Finding] = []

        for indicator_type in sorted(
            analysis.types,
            key=lambda item: item.value,
        ):
            metadata = self.METADATA.get(indicator_type)

            if metadata is None:
                continue

            (
                title,
                severity,
                confidence,
                cwe,
                owasp,
            ) = metadata

            indicators = [
                indicator
                for indicator in analysis.indicators
                if indicator.type == indicator_type
            ]

            evidence_lines = [
                indicator.evidence
                for indicator in indicators
            ]

            details: list[str] = []

            for indicator in indicators:
                if indicator.name is not None:
                    details.append(
                        f"name={indicator.name}"
                    )

                if indicator.value is not None:
                    details.append(
                        f"value={indicator.value}"
                    )

            evidence = "\n".join(evidence_lines)

            if details:
                evidence += "\n" + "\n".join(details)

            description = (
                f"{title}. "
                "This is an analytical HTTP method security "
                "indicator and does not by itself prove a "
                "vulnerability. Controlled validation of method "
                "authorization and server behavior is required."
            )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=description,
                    evidence=evidence,
                    remediation=self.REMEDIATION,
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
