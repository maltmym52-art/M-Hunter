from collections import defaultdict

from m_hunter.analyzers.ldap_injection import (
    LDAPInjectionAnalysis,
    LDAPInjectionIndicatorType,
)
from m_hunter.core.finding import Finding


class LDAPInjectionFindingAnalyzer:
    METADATA = {
        LDAPInjectionIndicatorType.LDAP_PARAMETER: (
            "LDAP-related parameter",
            "Info",
            "High",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.FILTER_PARAMETER: (
            "LDAP filter parameter",
            "Info",
            "High",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.SEARCH_PARAMETER: (
            "LDAP search parameter",
            "Info",
            "High",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.LDAP_MARKER: (
            "LDAP-related input marker",
            "Info",
            "Medium",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.FILTER_SYNTAX: (
            "LDAP filter syntax detected",
            "Medium",
            "Medium",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.WILDCARD: (
            "LDAP wildcard detected",
            "Low",
            "Medium",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.GROUPING_OPERATOR: (
            "LDAP grouping operator detected",
            "Medium",
            "Medium",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.LOGICAL_OPERATOR: (
            "LDAP logical operator detected",
            "Medium",
            "Medium",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.ATTRIBUTE_OPERATOR: (
            "LDAP attribute operator detected",
            "Medium",
            "Medium",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.LDAP_ESCAPE_SEQUENCE: (
            "LDAP escape sequence detected",
            "Medium",
            "Medium",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.LDAP_ERROR: (
            "LDAP error indicator detected",
            "Medium",
            "High",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.LDAP_RESULT: (
            "LDAP result indicator detected",
            "Medium",
            "Medium",
            "CWE-90",
            "A03:2021",
        ),
        LDAPInjectionIndicatorType.USER_CONTROLLED_FILTER: (
            "User-controlled LDAP filter",
            "High",
            "Medium",
            "CWE-90",
            "A03:2021",
        ),
    }

    def analyze(
        self,
        *,
        analysis: LDAPInjectionAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, LDAPInjectionAnalysis):
            raise TypeError(
                "analysis must be an LDAPInjectionAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        grouped = defaultdict(list)

        for indicator in analysis.indicators:
            grouped[indicator.type].append(indicator)

        findings: list[Finding] = []

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
                        "LDAP-injection-related indicators were detected. "
                        "Indicator presence alone does not prove LDAP "
                        "injection; controlled validation is required."
                    ),
                    evidence=evidence,
                    remediation=(
                        "Avoid constructing LDAP filters from untrusted "
                        "input. Use parameterized LDAP APIs where available, "
                        "apply strict input validation and allowlists, "
                        "escape LDAP filter metacharacters correctly, and "
                        "enforce least-privilege access."
                    ),
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
