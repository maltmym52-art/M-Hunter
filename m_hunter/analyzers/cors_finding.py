from m_hunter.analyzers.cors import CORSAnalyzer
from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.core.finding import Finding


class CORSFindingAnalyzer(FindingAnalyzer):
    name = "cors_findings"
    description = "Converts CORS analysis issues into findings"

    ISSUE_METADATA = {
        "wildcard_origin_with_credentials": {
            "title": "CORS Wildcard Origin with Credentials",
            "severity": "High",
            "confidence": "High",
            "description": (
                "The response enables CORS credentials while also "
                "allowing a wildcard origin."
            ),
            "remediation": (
                "Do not combine a wildcard Access-Control-Allow-Origin "
                "with credentialed CORS. Use an explicit trusted-origin "
                "allowlist."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        "origin_with_credentials": {
            "title": "Credentialed CORS for Explicit Origin",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The response allows credentials for an explicit origin. "
                "The allowed origin should be validated against a strict "
                "trusted-origin policy."
            ),
            "remediation": (
                "Validate the request Origin against a strict allowlist "
                "before returning credentialed CORS headers."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        "null_origin_allowed": {
            "title": "CORS Allows null Origin",
            "severity": "Medium",
            "confidence": "High",
            "description": (
                "The response explicitly allows the null origin, which "
                "can broaden the set of contexts permitted by CORS."
            ),
            "remediation": (
                "Avoid allowing the null origin unless it is explicitly "
                "required and understood by the application."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        "wildcard_methods": {
            "title": "CORS Allows Wildcard Methods",
            "severity": "Low",
            "confidence": "High",
            "description": (
                "The CORS policy allows all methods through a wildcard "
                "Access-Control-Allow-Methods value."
            ),
            "remediation": (
                "Restrict Access-Control-Allow-Methods to the HTTP "
                "methods required by the application."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        "wildcard_headers": {
            "title": "CORS Allows Wildcard Headers",
            "severity": "Low",
            "confidence": "High",
            "description": (
                "The CORS policy allows all request headers through a "
                "wildcard Access-Control-Allow-Headers value."
            ),
            "remediation": (
                "Restrict Access-Control-Allow-Headers to the headers "
                "required by the application."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
    }

    def analyze(
        self,
        analysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, dict):
            raise TypeError(
                "analysis must be a dictionary"
            )

        findings: list[Finding] = []

        for issue in analysis.get("issues", []):
            issue_name = issue.get("issue")
            metadata = self.ISSUE_METADATA.get(issue_name)

            if metadata is None:
                continue

            evidence = (
                f"HTTP response from {endpoint or target} "
                f"contains a CORS configuration associated with "
                f"the detected issue: {issue_name}."
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
        analyzer = CORSAnalyzer()
        analysis = analyzer.analyze(http_analysis)

        resolved_target = target or http_analysis.response.url
        resolved_endpoint = (
            endpoint or http_analysis.response.url
        )

        return self.analyze(
            {
                "issues": [
                    {
                        "issue": issue.issue,
                        "severity": issue.severity,
                        "description": issue.description,
                    }
                    for issue in analysis.issues
                ]
            },
            target=resolved_target,
            endpoint=resolved_endpoint,
        )
