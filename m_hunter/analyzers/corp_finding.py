from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.corp import CORPAnalysis, CORPIndicatorType
from m_hunter.core.finding import Finding


class CORPFindingAnalyzer(FindingAnalyzer):
    name = "corp_finding"

    METADATA = {
        CORPIndicatorType.POLICY_PRESENT: (
            "Cross-Origin-Resource-Policy header is present",
            "Info",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CORPIndicatorType.POLICY_MISSING: (
            "Cross-Origin-Resource-Policy header is missing",
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CORPIndicatorType.SAME_ORIGIN: (
            "Cross-Origin-Resource-Policy uses same-origin",
            "Info",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CORPIndicatorType.SAME_SITE: (
            "Cross-Origin-Resource-Policy uses same-site",
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CORPIndicatorType.CROSS_ORIGIN: (
            "Cross-Origin-Resource-Policy uses cross-origin",
            "Medium",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CORPIndicatorType.INVALID_POLICY: (
            "Cross-Origin-Resource-Policy contains an invalid policy",
            "Medium",
            "High",
            "CWE-16",
            "A05:2021",
        ),
        CORPIndicatorType.MULTIPLE_POLICIES: (
            "Multiple Cross-Origin-Resource-Policy values are present",
            "Low",
            "Medium",
            "CWE-16",
            "A05:2021",
        ),
    }

    def analyze(
        self,
        analysis: CORPAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, CORPAnalysis):
            raise TypeError(
                "analysis must be an instance of CORPAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError(
                "target must be a non-empty string"
            )

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError(
                "endpoint must be a string or None"
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

            if indicator.type == CORPIndicatorType.POLICY_MISSING:
                evidence = (
                    "Cross-Origin-Resource-Policy header is missing"
                )
            elif indicator.value:
                evidence = (
                    f"{indicator.name}: {indicator.value}"
                )
            else:
                evidence = indicator.name

            description = (
                "The response contains a "
                "Cross-Origin-Resource-Policy-related condition "
                "that should be reviewed in the context of the "
                "application's cross-origin resource requirements."
            )

            if indicator.type == CORPIndicatorType.POLICY_MISSING:
                description = (
                    "The response does not define a "
                    "Cross-Origin-Resource-Policy header. "
                    "Resources without an explicit CORP policy "
                    "may be available to cross-origin contexts "
                    "according to browser and resource-loading "
                    "rules."
                )

            elif indicator.type == CORPIndicatorType.SAME_ORIGIN:
                description = (
                    "The response defines CORP as same-origin, "
                    "restricting cross-origin resource loading."
                )

            elif indicator.type == CORPIndicatorType.SAME_SITE:
                description = (
                    "The response defines CORP as same-site, "
                    "allowing resource loading within the same site "
                    "while restricting other cross-origin contexts."
                )

            elif indicator.type == CORPIndicatorType.CROSS_ORIGIN:
                description = (
                    "The response defines CORP as cross-origin, "
                    "which permits cross-origin resource loading."
                )

            elif indicator.type == CORPIndicatorType.INVALID_POLICY:
                description = (
                    "The response contains a value that does not "
                    "match a recognized Cross-Origin-Resource-Policy "
                    "directive."
                )

            elif indicator.type == CORPIndicatorType.MULTIPLE_POLICIES:
                description = (
                    "Multiple Cross-Origin-Resource-Policy values "
                    "were observed. Their interaction should be "
                    "reviewed because inconsistent policies can "
                    "produce ambiguous behavior."
                )

            remediation = (
                "Define a Cross-Origin-Resource-Policy appropriate "
                "for the resource. Use same-origin or same-site "
                "when cross-origin loading is not required, and "
                "use cross-origin only when intentional."
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
                    remediation=remediation,
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
