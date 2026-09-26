from m_hunter.analyzers.nosql_injection import (
    NoSQLInjectionAnalysis,
    NoSQLInjectionIndicatorType,
)
from m_hunter.core.finding import Finding


class NoSQLInjectionFindingAnalyzer:
    name = "nosql_injection_finding"

    _METADATA = {
        NoSQLInjectionIndicatorType.MONGODB_OPERATOR: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-943",
            "owasp": "A03:2021",
        },
        NoSQLInjectionIndicatorType.QUERY_OPERATOR: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-943",
            "owasp": "A03:2021",
        },
        NoSQLInjectionIndicatorType.JSON_OPERATOR: {
            "severity": "Info",
            "confidence": "Low",
            "cwe": "CWE-943",
            "owasp": "A03:2021",
        },
        NoSQLInjectionIndicatorType.REGEX_OPERATOR: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-943",
            "owasp": "A03:2021",
        },
        NoSQLInjectionIndicatorType.JAVASCRIPT_OPERATOR: {
            "severity": "High",
            "confidence": "Medium",
            "cwe": "CWE-943",
            "owasp": "A03:2021",
        },
        NoSQLInjectionIndicatorType.DOLLAR_PREFIX: {
            "severity": "Medium",
            "confidence": "Low",
            "cwe": "CWE-943",
            "owasp": "A03:2021",
        },
        NoSQLInjectionIndicatorType.DOT_NOTATION: {
            "severity": "Low",
            "confidence": "Low",
            "cwe": "CWE-943",
            "owasp": "A03:2021",
        },
        NoSQLInjectionIndicatorType.QUERY_OBJECT: {
            "severity": "Info",
            "confidence": "Low",
            "cwe": "CWE-943",
            "owasp": "A03:2021",
        },
        NoSQLInjectionIndicatorType.DATABASE_ERROR: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-943",
            "owasp": "A03:2021",
        },
        NoSQLInjectionIndicatorType.MONGODB_CONTEXT: {
            "severity": "Info",
            "confidence": "Low",
            "cwe": "CWE-943",
            "owasp": "A03:2021",
        },
    }

    def create_findings(
        self,
        analysis: NoSQLInjectionAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, NoSQLInjectionAnalysis):
            raise TypeError("analysis must be NoSQLInjectionAnalysis")

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
                        "Use parameterized and strongly typed query construction, "
                        "validate expected input types, reject unexpected query "
                        "operators, and avoid passing user-controlled objects "
                        "directly into database queries."
                    ),
                    cwe=metadata["cwe"],
                    owasp=metadata["owasp"],
                )
            )

        return findings

    def analyze(
        self,
        analysis: NoSQLInjectionAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        return self.create_findings(
            analysis,
            target,
            endpoint,
        )

    @staticmethod
    def _title_for(
        indicator_type: NoSQLInjectionIndicatorType,
    ) -> str:
        titles = {
            NoSQLInjectionIndicatorType.MONGODB_OPERATOR:
                "NoSQL Injection Indicator: MongoDB Operator",
            NoSQLInjectionIndicatorType.QUERY_OPERATOR:
                "NoSQL Query Operator Detected",
            NoSQLInjectionIndicatorType.JSON_OPERATOR:
                "NoSQL JSON Query Context Detected",
            NoSQLInjectionIndicatorType.REGEX_OPERATOR:
                "NoSQL Regex Operator Detected",
            NoSQLInjectionIndicatorType.JAVASCRIPT_OPERATOR:
                "NoSQL JavaScript Operator Detected",
            NoSQLInjectionIndicatorType.DOLLAR_PREFIX:
                "NoSQL Dollar-Prefixed Operator Detected",
            NoSQLInjectionIndicatorType.DOT_NOTATION:
                "NoSQL Dot Notation Detected",
            NoSQLInjectionIndicatorType.QUERY_OBJECT:
                "NoSQL Query Object Detected",
            NoSQLInjectionIndicatorType.DATABASE_ERROR:
                "NoSQL Database Error Indicator",
            NoSQLInjectionIndicatorType.MONGODB_CONTEXT:
                "MongoDB Context Detected",
        }

        return titles[indicator_type]

    @staticmethod
    def _description_for(
        indicator_type: NoSQLInjectionIndicatorType,
    ) -> str:
        if indicator_type in {
            NoSQLInjectionIndicatorType.MONGODB_OPERATOR,
            NoSQLInjectionIndicatorType.QUERY_OPERATOR,
            NoSQLInjectionIndicatorType.REGEX_OPERATOR,
            NoSQLInjectionIndicatorType.JAVASCRIPT_OPERATOR,
            NoSQLInjectionIndicatorType.DOLLAR_PREFIX,
        }:
            return (
                "A NoSQL query operator was observed in application input. "
                "This is an indicator associated with NoSQL injection, but "
                "the presence of an operator alone does not prove that the "
                "application is vulnerable or exploitable."
            )

        if indicator_type == NoSQLInjectionIndicatorType.DATABASE_ERROR:
            return (
                "A database error marker associated with NoSQL technologies "
                "was observed. Additional controlled validation is required "
                "to determine whether user input influences a database query."
            )

        return (
            "A characteristic associated with NoSQL query processing was "
            "observed. This indicator alone does not establish an exploitable "
            "NoSQL injection vulnerability."
        )
