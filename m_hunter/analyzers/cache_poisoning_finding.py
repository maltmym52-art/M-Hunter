from m_hunter.analyzers.cache_poisoning import (
    CachePoisoningAnalysis,
    CachePoisoningIndicator,
    CachePoisoningIndicatorType,
)
from m_hunter.core.finding import Finding


class CachePoisoningFindingAnalyzer:
    METADATA = {
        CachePoisoningIndicatorType.CACHE_HEADER: (
            "Info",
            "High",
            "CWE-524",
            "A05:2021",
        ),
        CachePoisoningIndicatorType.CACHE_STATUS: (
            "Info",
            "High",
            "CWE-524",
            "A05:2021",
        ),
        CachePoisoningIndicatorType.CACHE_CONTROL: (
            "Info",
            "High",
            "CWE-524",
            "A05:2021",
        ),
        CachePoisoningIndicatorType.VARY_HEADER: (
            "Info",
            "High",
            "CWE-524",
            "A05:2021",
        ),
        CachePoisoningIndicatorType.CACHE_KEY_INDICATOR: (
            "Info",
            "Medium",
            "CWE-524",
            "A05:2021",
        ),
        CachePoisoningIndicatorType.AGE_HEADER: (
            "Info",
            "High",
            "CWE-524",
            "A05:2021",
        ),
        CachePoisoningIndicatorType.ETAG_HEADER: (
            "Info",
            "High",
            "CWE-524",
            "A05:2021",
        ),
        CachePoisoningIndicatorType.UNKEYED_INPUT: (
            "Medium",
            "Medium",
            "CWE-444",
            "A05:2021",
        ),
        CachePoisoningIndicatorType.RESPONSE_VARIATION: (
            "Medium",
            "Medium",
            "CWE-524",
            "A05:2021",
        ),
    }

    REMEDIATION = (
        "Review cache configuration and ensure security-sensitive inputs are "
        "properly included in the cache key or rejected. Avoid caching "
        "responses that depend on unkeyed request inputs. Configure trusted "
        "proxy/CDN headers explicitly and verify cache behavior for "
        "authentication, authorization, and user-specific content."
    )

    def create_findings(
        self,
        analysis: CachePoisoningAnalysis,
        target: str,
        *,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, CachePoisoningAnalysis):
            raise TypeError("analysis must be CachePoisoningAnalysis")

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
        indicator: CachePoisoningIndicator,
        target: str,
        *,
        endpoint: str | None,
        parameter: str | None,
    ) -> Finding | None:
        metadata = self.METADATA.get(indicator.type)

        if metadata is None:
            return None

        severity, confidence, cwe, owasp = metadata

        title_map = {
            CachePoisoningIndicatorType.CACHE_HEADER:
                "Cache header detected",
            CachePoisoningIndicatorType.CACHE_STATUS:
                "Cache behavior detected",
            CachePoisoningIndicatorType.CACHE_CONTROL:
                "Cache-Control behavior detected",
            CachePoisoningIndicatorType.VARY_HEADER:
                "Vary header affects cache behavior",
            CachePoisoningIndicatorType.CACHE_KEY_INDICATOR:
                "Potential cache key indicator detected",
            CachePoisoningIndicatorType.AGE_HEADER:
                "Cached response age detected",
            CachePoisoningIndicatorType.ETAG_HEADER:
                "ETag cache validator detected",
            CachePoisoningIndicatorType.UNKEYED_INPUT:
                "Potential unkeyed cache input detected",
            CachePoisoningIndicatorType.RESPONSE_VARIATION:
                "Response variation detected",
        }

        description = (
            f"Cache-related behavior was observed through the indicator "
            f"'{indicator.name}'. This is an analytical indicator and does "
            f"not by itself prove exploitable cache poisoning."
        )

        evidence = (
            f"Indicator: {indicator.type.value}\n"
            f"Name: {indicator.name}\n"
            f"Value: {indicator.value}\n"
            f"Evidence: {indicator.evidence}"
        )

        return Finding(
            title=title_map[indicator.type],
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
