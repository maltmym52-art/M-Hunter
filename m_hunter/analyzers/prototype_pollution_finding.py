from typing import Any

from m_hunter.analyzers.prototype_pollution import (
    PrototypePollutionAnalysis,
    PrototypePollutionIndicatorType,
)
from m_hunter.core.finding import Finding


class PrototypePollutionFindingAnalyzer:
    name = "prototype_pollution_finding"

    _METADATA = {
        PrototypePollutionIndicatorType.PROTO_KEY: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
        PrototypePollutionIndicatorType.CONSTRUCTOR_KEY: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
        PrototypePollutionIndicatorType.PROTOTYPE_KEY: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
        PrototypePollutionIndicatorType.NESTED_OBJECT: {
            "severity": "Info",
            "confidence": "Low",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
        PrototypePollutionIndicatorType.POLLUTION_MARKER: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
        PrototypePollutionIndicatorType.JAVASCRIPT_CONTEXT: {
            "severity": "Info",
            "confidence": "Low",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
        PrototypePollutionIndicatorType.JSON_OBJECT: {
            "severity": "Info",
            "confidence": "Low",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
        PrototypePollutionIndicatorType.QUERY_PARAMETER: {
            "severity": "Info",
            "confidence": "Low",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
        PrototypePollutionIndicatorType.REQUEST_BODY: {
            "severity": "Info",
            "confidence": "Low",
            "cwe": "CWE-1321",
            "owasp": "A03:2021",
        },
    }

    def create_findings(
        self,
        analysis: PrototypePollutionAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, PrototypePollutionAnalysis):
            raise TypeError("analysis must be PrototypePollutionAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        findings: list[Finding] = []

        for indicator in analysis.indicators:
            metadata = self._METADATA[indicator.type]

            findings.append(
                Finding(
                    title=self._title_for(indicator.type),
                    severity=metadata["severity"],
                    confidence=metadata["confidence"],
                    target=target,
                    endpoint=endpoint,
                    parameter=indicator.name,
                    description=self._description_for(indicator.type),
                    evidence=indicator.evidence,
                    remediation=(
                        "Avoid unsafe recursive object merging or property assignment. "
                        "Reject prototype-related keys such as __proto__, constructor, "
                        "and prototype when they are not explicitly required, and use "
                        "safe object handling patterns."
                    ),
                    cwe=metadata["cwe"],
                    owasp=metadata["owasp"],
                )
            )

        return findings

    @staticmethod
    def _title_for(indicator_type: PrototypePollutionIndicatorType) -> str:
        titles = {
            PrototypePollutionIndicatorType.PROTO_KEY:
                "Prototype Pollution Indicator: __proto__",
            PrototypePollutionIndicatorType.CONSTRUCTOR_KEY:
                "Prototype Pollution Indicator: constructor",
            PrototypePollutionIndicatorType.PROTOTYPE_KEY:
                "Prototype Pollution Indicator: prototype",
            PrototypePollutionIndicatorType.NESTED_OBJECT:
                "Nested Object Input Detected",
            PrototypePollutionIndicatorType.POLLUTION_MARKER:
                "Potential Prototype Pollution Marker",
            PrototypePollutionIndicatorType.JAVASCRIPT_CONTEXT:
                "JavaScript Context Detected",
            PrototypePollutionIndicatorType.JSON_OBJECT:
                "JSON Object Input Detected",
            PrototypePollutionIndicatorType.QUERY_PARAMETER:
                "Prototype Pollution Query Input",
            PrototypePollutionIndicatorType.REQUEST_BODY:
                "Prototype Pollution Request Body Input",
        }
        return titles[indicator_type]

    @staticmethod
    def _description_for(
        indicator_type: PrototypePollutionIndicatorType,
    ) -> str:
        if indicator_type in {
            PrototypePollutionIndicatorType.PROTO_KEY,
            PrototypePollutionIndicatorType.CONSTRUCTOR_KEY,
            PrototypePollutionIndicatorType.PROTOTYPE_KEY,
        }:
            return (
                "A prototype-related property name was observed in application "
                "input. This is an indicator associated with JavaScript prototype "
                "pollution, but the presence of the key alone does not prove that "
                "prototype pollution is exploitable."
            )

        if indicator_type == PrototypePollutionIndicatorType.POLLUTION_MARKER:
            return (
                "A response marker associated with possible prototype pollution "
                "was observed. Additional controlled validation is required."
            )

        return (
            "An input or response characteristic associated with prototype "
            "pollution analysis was observed. This indicator alone does not "
            "establish an exploitable vulnerability."
        )


    def analyze(
        self,
        analysis: PrototypePollutionAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        return self.create_findings(analysis, target, endpoint)
