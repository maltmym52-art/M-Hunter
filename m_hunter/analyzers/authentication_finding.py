from m_hunter.analyzers.authentication import (
    AuthenticationAnalyzer,
)
from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.core.finding import Finding


class AuthenticationFindingAnalyzer(FindingAnalyzer):
    name = "authentication_findings"
    description = "Converts authentication analysis into findings"

    SCHEME_METADATA = {
        "Basic": {
            "title": "Basic Authentication Detected",
            "severity": "Low",
            "confidence": "High",
            "description": (
                "The application uses HTTP Basic Authentication. "
                "Basic authentication transmits credentials using "
                "base64 encoding and should only be used over HTTPS."
            ),
            "remediation": (
                "Use HTTPS for all Basic Authentication traffic and "
                "consider stronger authentication mechanisms where "
                "appropriate."
            ),
            "cwe": "CWE-319",
            "owasp": "A07:2021",
        },
    }

    def analyze(
        self,
        analysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not hasattr(analysis, "authentication_scheme"):
            raise TypeError(
                "analysis must be an AuthenticationAnalysis"
            )

        findings: list[Finding] = []

        scheme = analysis.authentication_scheme
        metadata = self.SCHEME_METADATA.get(scheme)

        if metadata is not None:
            evidence = (
                f"HTTP request from {endpoint or target} "
                f"uses the {scheme} authentication scheme."
            )

            findings.append(
                self.create_finding(
                    title=metadata["title"],
                    severity=metadata["severity"],
                    confidence=metadata["confidence"],
                    target=target,
                    endpoint=endpoint,
                    description=metadata["description"],
                    evidence=evidence,
                    remediation=metadata["remediation"],
                    cwe=metadata["cwe"],
                    owasp=metadata["owasp"],
                )
            )

        return findings

    def analyze_http(
        self,
        http_analysis,
        *,
        target: str | None = None,
        endpoint: str | None = None,
    ) -> list[Finding]:
        analyzer = AuthenticationAnalyzer()
        analysis = analyzer.analyze(http_analysis)

        resolved_target = (
            target or http_analysis.response.url
        )
        resolved_endpoint = (
            endpoint or http_analysis.response.url
        )

        return self.analyze(
            analysis,
            target=resolved_target,
            endpoint=resolved_endpoint,
        )
