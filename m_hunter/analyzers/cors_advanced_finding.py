from m_hunter.analyzers.cors_advanced import (
    CORSAdvancedAnalysis,
    CORSAdvancedIndicatorType,
)
from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.core.finding import Finding


class CORSAdvancedFindingAnalyzer(FindingAnalyzer):
    name = "cors_advanced_findings"
    description = "Converts advanced CORS indicators into findings"

    INDICATOR_METADATA = {
        CORSAdvancedIndicatorType.ORIGIN_REFLECTION: {
            "title": "CORS Origin Reflection",
            "severity": "Medium",
            "confidence": "High",
            "description": (
                "The supplied Origin value was reflected by "
                "Access-Control-Allow-Origin."
            ),
            "remediation": (
                "Validate Origin against a strict trusted-origin "
                "allowlist instead of reflecting arbitrary values."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.REFLECTED_ARBITRARY_ORIGIN: {
            "title": "CORS Allows Arbitrary Origin",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "The CORS response appears to permit an arbitrary "
                "candidate origin through its Access-Control-Allow-Origin "
                "policy."
            ),
            "remediation": (
                "Restrict Access-Control-Allow-Origin to explicitly "
                "trusted origins."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.CREDENTIALED_ORIGIN_REFLECTION: {
            "title": "Credentialed CORS Origin Reflection",
            "severity": "High",
            "confidence": "High",
            "description": (
                "The supplied Origin was reflected while credentialed "
                "CORS was enabled."
            ),
            "remediation": (
                "Use a strict trusted-origin allowlist and only enable "
                "credentials for explicitly trusted origins."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.NULL_ORIGIN_REFLECTION: {
            "title": "CORS Reflects null Origin",
            "severity": "Medium",
            "confidence": "High",
            "description": (
                "The null Origin was reflected by the CORS policy."
            ),
            "remediation": (
                "Do not trust the null origin unless it is explicitly "
                "required by the application's security model."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.SUBDOMAIN_TRUST: {
            "title": "Broad CORS Subdomain Trust",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The CORS policy appears to broadly trust a related "
                "subdomain rather than an exact origin."
            ),
            "remediation": (
                "Validate complete origins and avoid broad subdomain "
                "trust unless every trusted subdomain is controlled."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.PREFIX_TRUST: {
            "title": "CORS Prefix-Based Origin Trust",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The CORS policy appears to use prefix-based matching "
                "for allowed origins."
            ),
            "remediation": (
                "Compare normalized origins exactly instead of using "
                "prefix-based matching."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.SUFFIX_TRUST: {
            "title": "CORS Suffix-Based Origin Trust",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The CORS policy appears to use suffix-based matching "
                "for allowed origins."
            ),
            "remediation": (
                "Compare normalized origins exactly and avoid suffix "
                "matching that can trust unintended domains."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.WILDCARD_CREDENTIALS: {
            "title": "CORS Wildcard Origin with Credentials",
            "severity": "High",
            "confidence": "High",
            "description": (
                "Wildcard Access-Control-Allow-Origin was observed "
                "together with credentialed CORS."
            ),
            "remediation": (
                "Do not combine wildcard origins with credentialed CORS. "
                "Use explicit trusted origins."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.VARY_ORIGIN_MISSING: {
            "title": "CORS Origin Variation without Vary: Origin",
            "severity": "Low",
            "confidence": "Medium",
            "description": (
                "The response appears to vary according to Origin "
                "without advertising Origin in the Vary header."
            ),
            "remediation": (
                "When responses vary by Origin, include Vary: Origin "
                "where appropriate to prevent intermediary cache "
                "confusion."
            ),
            "cwe": "CWE-444",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.PREFLIGHT_ALLOWED: {
            "title": "CORS Preflight Allowed",
            "severity": "Info",
            "confidence": "High",
            "description": (
                "The response exposes CORS preflight-related policy."
            ),
            "remediation": (
                "Restrict preflight permissions to the methods and "
                "headers required by the application."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.PREFLIGHT_CREDENTIALS: {
            "title": "CORS Preflight Allows Credentials",
            "severity": "Low",
            "confidence": "High",
            "description": (
                "The preflight response exposes credentialed CORS "
                "configuration."
            ),
            "remediation": (
                "Enable credentials only for explicitly trusted origins."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.PREFLIGHT_METHODS: {
            "title": "CORS Preflight Methods Exposed",
            "severity": "Info",
            "confidence": "High",
            "description": (
                "The preflight response exposes allowed HTTP methods."
            ),
            "remediation": (
                "Limit Access-Control-Allow-Methods to methods actually "
                "required by the application."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.PREFLIGHT_HEADERS: {
            "title": "CORS Preflight Headers Exposed",
            "severity": "Info",
            "confidence": "High",
            "description": (
                "The preflight response exposes allowed request headers."
            ),
            "remediation": (
                "Limit Access-Control-Allow-Headers to headers actually "
                "required by the application."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.CREDENTIALS_ENABLED: {
            "title": "Credentialed CORS Enabled",
            "severity": "Info",
            "confidence": "High",
            "description": (
                "The response enables credentialed CORS."
            ),
            "remediation": (
                "Ensure credentialed CORS is restricted to explicitly "
                "trusted origins."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.ACCESS_CONTROL_ALLOW_ORIGIN_PRESENT: {
            "title": "CORS Allow-Origin Header Present",
            "severity": "Info",
            "confidence": "High",
            "description": (
                "The response contains an Access-Control-Allow-Origin "
                "header."
            ),
            "remediation": (
                "Review the allowed origin against the application's "
                "trusted-origin policy."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
        CORSAdvancedIndicatorType.ACCESS_CONTROL_ALLOW_CREDENTIALS_PRESENT: {
            "title": "CORS Allow-Credentials Header Present",
            "severity": "Info",
            "confidence": "High",
            "description": (
                "The response contains an "
                "Access-Control-Allow-Credentials header."
            ),
            "remediation": (
                "Ensure credentialed CORS is restricted to trusted "
                "origins."
            ),
            "cwe": "CWE-942",
            "owasp": "A05:2021",
        },
    }

    def analyze(
        self,
        analysis: CORSAdvancedAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(
            analysis,
            CORSAdvancedAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of CORSAdvancedAnalysis"
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

        for indicator in analysis.indicators:
            metadata = self.INDICATOR_METADATA.get(
                indicator.type
            )

            if metadata is None:
                continue

            evidence = indicator.evidence

            if indicator.value is not None:
                evidence = (
                    f"{evidence} Observed value: "
                    f"{indicator.value}"
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
