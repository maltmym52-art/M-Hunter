from m_hunter.analyzers.web_cache_deception import (
    WebCacheDeceptionAnalysis,
    WebCacheDeceptionIndicator,
    WebCacheDeceptionIndicatorType,
)
from m_hunter.core.finding import Finding


class WebCacheDeceptionFindingAnalyzer:
    METADATA = {
        WebCacheDeceptionIndicatorType.CACHE_HEADER: (
            "Info", "High", "CWE-524", "A05:2021",
        ),
        WebCacheDeceptionIndicatorType.CACHEABLE_RESPONSE: (
            "Low", "High", "CWE-524", "A05:2021",
        ),
        WebCacheDeceptionIndicatorType.STATIC_EXTENSION: (
            "Info", "High", "CWE-524", "A05:2021",
        ),
        WebCacheDeceptionIndicatorType.PATH_VARIATION: (
            "Medium", "Medium", "CWE-524", "A05:2021",
        ),
        WebCacheDeceptionIndicatorType.SENSITIVE_CONTENT: (
            "Medium", "Medium", "CWE-524", "A05:2021",
        ),
        WebCacheDeceptionIndicatorType.PRIVATE_CONTENT: (
            "Info", "High", "CWE-524", "A05:2021",
        ),
        WebCacheDeceptionIndicatorType.CACHE_STATUS: (
            "Info", "High", "CWE-524", "A05:2021",
        ),
        WebCacheDeceptionIndicatorType.AGE_HEADER: (
            "Info", "High", "CWE-524", "A05:2021",
        ),
        WebCacheDeceptionIndicatorType.VARY_HEADER: (
            "Info", "High", "CWE-524", "A05:2021",
        ),
        WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH: (
            "Medium", "Medium", "CWE-436", "A05:2021",
        ),
    }

    TITLES = {
        WebCacheDeceptionIndicatorType.CACHE_HEADER:
            "Cache-Control behavior detected",
        WebCacheDeceptionIndicatorType.CACHEABLE_RESPONSE:
            "Potentially cacheable response detected",
        WebCacheDeceptionIndicatorType.STATIC_EXTENSION:
            "Static-looking path detected",
        WebCacheDeceptionIndicatorType.PATH_VARIATION:
            "Potential cache deception path variation detected",
        WebCacheDeceptionIndicatorType.SENSITIVE_CONTENT:
            "Potentially sensitive content detected",
        WebCacheDeceptionIndicatorType.PRIVATE_CONTENT:
            "Private cache directive detected",
        WebCacheDeceptionIndicatorType.CACHE_STATUS:
            "Cache status detected",
        WebCacheDeceptionIndicatorType.AGE_HEADER:
            "Cached response age detected",
        WebCacheDeceptionIndicatorType.VARY_HEADER:
            "Vary header affects cache behavior",
        WebCacheDeceptionIndicatorType.CONTENT_TYPE_MISMATCH:
            "Static-looking path returned mismatched content type",
    }

    REMEDIATION = (
        "Avoid caching user-specific or sensitive responses. Configure "
        "cache rules so dynamic routes cannot be treated as static "
        "resources, and ensure cache keys and path normalization are "
        "consistent. Use appropriate private/no-store directives for "
        "sensitive content and verify CDN/proxy behavior."
    )

    def create_findings(
        self,
        analysis: WebCacheDeceptionAnalysis,
        target: str,
        *,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, WebCacheDeceptionAnalysis):
            raise TypeError("analysis must be WebCacheDeceptionAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        if not analysis.detected:
            return []

        findings: list[Finding] = []

        for indicator in analysis.indicators:
            finding = self._create_finding(
                indicator,
                target,
                endpoint=endpoint,
                parameter=parameter,
            )

            if finding is not None:
                findings.append(finding)

        return findings

    def _create_finding(
        self,
        indicator: WebCacheDeceptionIndicator,
        target: str,
        *,
        endpoint: str | None,
        parameter: str | None,
    ) -> Finding | None:
        metadata = self.METADATA.get(indicator.type)

        if metadata is None:
            return None

        severity, confidence, cwe, owasp = metadata

        title = self.TITLES[indicator.type]

        description = (
            f"Web cache deception related behavior was observed through "
            f"the indicator '{indicator.name}'. This is an analytical "
            f"indicator and does not by itself prove exploitable web cache "
            f"deception."
        )

        evidence = (
            f"Indicator: {indicator.type.value}\n"
            f"Name: {indicator.name}\n"
            f"Value: {indicator.value}\n"
            f"Evidence: {indicator.evidence}"
        )

        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
            description=description,
            evidence=evidence,
            remediation=self.REMEDIATION,
            cwe=cwe,
            owasp=owasp,
        )
