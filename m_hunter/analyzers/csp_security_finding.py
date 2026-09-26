from m_hunter.analyzers.csp_security import (
    CSPAnalysis,
    CSPIndicatorType,
)
from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.core.finding import Finding


class CSPFindingAnalyzer(FindingAnalyzer):
    name = "csp_security_finding"

    METADATA = {
        CSPIndicatorType.CSP_PRESENT: (
            "Informational",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.CSP_REPORT_ONLY: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.WILDCARD_SOURCE: (
            "Medium",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.UNSAFE_INLINE: (
            "Medium",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.UNSAFE_EVAL: (
            "Medium",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.UNSAFE_HASHES: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.NONCE_SOURCE: (
            "Info",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.DATA_SOURCE: (
            "Medium",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.BLOB_SOURCE: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.OBJECT_NONE: (
            "Info",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.BASE_NONE: (
            "Info",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.FRAME_ANCESTORS_NONE: (
            "Info",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        CSPIndicatorType.FRAME_ANCESTORS_WILDCARD: (
            "Medium",
            "High",
            "CWE-1021",
            "A05:2021",
        ),
        CSPIndicatorType.SCRIPT_SRC_MISSING: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.DEFAULT_SRC_MISSING: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.SCRIPT_SRC_WILDCARD: (
            "High",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.CONNECT_SRC_WILDCARD: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.IMG_SRC_WILDCARD: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.STYLE_SRC_WILDCARD: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.FORM_ACTION_MISSING: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.UPGRADE_INSECURE_REQUESTS_MISSING: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
        CSPIndicatorType.BLOCK_ALL_MIXED_CONTENT_MISSING: (
            "Low",
            "High",
            "CWE-693",
            "A05:2021",
        ),
    }

    TITLES = {
        CSPIndicatorType.CSP_PRESENT:
            "Content Security Policy Present",
        CSPIndicatorType.CSP_REPORT_ONLY:
            "CSP Report-Only Policy",
        CSPIndicatorType.WILDCARD_SOURCE:
            "CSP Wildcard Source",
        CSPIndicatorType.UNSAFE_INLINE:
            "CSP Allows Unsafe Inline",
        CSPIndicatorType.UNSAFE_EVAL:
            "CSP Allows Unsafe Eval",
        CSPIndicatorType.UNSAFE_HASHES:
            "CSP Allows Unsafe Hashes",
        CSPIndicatorType.NONCE_SOURCE:
            "CSP Nonce Source",
        CSPIndicatorType.DATA_SOURCE:
            "CSP Allows Data Source",
        CSPIndicatorType.BLOB_SOURCE:
            "CSP Allows Blob Source",
        CSPIndicatorType.OBJECT_NONE:
            "CSP Object Source Restricted",
        CSPIndicatorType.BASE_NONE:
            "CSP Base URI Restricted",
        CSPIndicatorType.FRAME_ANCESTORS_NONE:
            "CSP Frame Ancestors Restricted",
        CSPIndicatorType.FRAME_ANCESTORS_WILDCARD:
            "CSP Frame Ancestors Wildcard",
        CSPIndicatorType.SCRIPT_SRC_MISSING:
            "CSP Script Source Missing",
        CSPIndicatorType.DEFAULT_SRC_MISSING:
            "CSP Default Source Missing",
        CSPIndicatorType.SCRIPT_SRC_WILDCARD:
            "CSP Script Source Wildcard",
        CSPIndicatorType.CONNECT_SRC_WILDCARD:
            "CSP Connect Source Wildcard",
        CSPIndicatorType.IMG_SRC_WILDCARD:
            "CSP Image Source Wildcard",
        CSPIndicatorType.STYLE_SRC_WILDCARD:
            "CSP Style Source Wildcard",
        CSPIndicatorType.FORM_ACTION_MISSING:
            "CSP Form Action Missing",
        CSPIndicatorType.UPGRADE_INSECURE_REQUESTS_MISSING:
            "CSP Upgrade Insecure Requests Missing",
        CSPIndicatorType.BLOCK_ALL_MIXED_CONTENT_MISSING:
            "CSP Mixed Content Protection Missing",
    }

    def analyze(
        self,
        analysis: CSPAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, CSPAnalysis):
            raise TypeError(
                "analysis must be an instance of CSPAnalysis"
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
            metadata = self.METADATA.get(
                indicator.type
            )

            if metadata is None:
                continue

            severity, confidence, cwe, owasp = metadata

            title = self.TITLES.get(
                indicator.type,
                indicator.type.value.replace(
                    "_",
                    " ",
                ).title(),
            )

            evidence = indicator.evidence

            if indicator.value:
                evidence = (
                    f"{evidence}; "
                    f"value={indicator.value}"
                )

            description = (
                "CSP analysis identified the following "
                "policy characteristic: "
                f"{indicator.type.value}. "
                "The indicator alone does not prove "
                "that a CSP-related vulnerability is "
                "exploitable."
            )

            remediation = (
                "Review the Content-Security-Policy and "
                "remove unnecessary broad or unsafe "
                "sources. Prefer restrictive directives "
                "and explicit trusted origins."
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
