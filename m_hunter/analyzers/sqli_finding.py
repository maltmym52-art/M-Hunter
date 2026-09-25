from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.sqli import SQLiAnalysis
from m_hunter.core.finding import Finding


class SQLiFindingAnalyzer(FindingAnalyzer):
    name = "sqli_findings"
    description = "Converts SQL injection indicators into findings"

    DATABASE_METADATA = {
        "mysql": {
            "title": "MySQL Error Disclosure",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The response exposes a MySQL database error "
                "associated with controlled input. This is an "
                "indicator that requires further validation."
            ),
        },
        "postgresql": {
            "title": "PostgreSQL Error Disclosure",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The response exposes a PostgreSQL database error. "
                "The error is an SQL injection indicator, not proof "
                "of exploitability by itself."
            ),
        },
        "mssql": {
            "title": "Microsoft SQL Server Error Disclosure",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The response exposes a Microsoft SQL Server error "
                "associated with the tested request."
            ),
        },
        "oracle": {
            "title": "Oracle Database Error Disclosure",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The response exposes an Oracle database error. "
                "Further controlled validation is required."
            ),
        },
        "sqlite": {
            "title": "SQLite Error Disclosure",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The response exposes a SQLite database error. "
                "The indicator alone does not prove SQL injection."
            ),
        },
        "generic": {
            "title": "SQL Database Error Disclosure",
            "severity": "Low",
            "confidence": "Low",
            "description": (
                "The response exposes a generic SQL/database error. "
                "Additional validation is required to determine "
                "whether SQL injection is present."
            ),
        },
    }

    REMEDIATION = (
        "Avoid exposing database errors to clients. Use generic "
        "application errors, parameterized queries, prepared "
        "statements, and appropriate server-side input handling."
    )

    def analyze(
        self,
        analysis: SQLiAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, SQLiAnalysis):
            raise TypeError("analysis must be an SQLiAnalysis")

        if not analysis.detected:
            return []

        findings: list[Finding] = []

        for category in analysis.categories:
            metadata = self.DATABASE_METADATA.get(
                category,
                self.DATABASE_METADATA["generic"],
            )

            category_indicators = [
                indicator
                for indicator in analysis.indicators
                if indicator.category == category
            ]

            evidence = [
                f"database category: {category}",
                f"indicator count: {len(category_indicators)}",
            ]

            for indicator in category_indicators:
                evidence.append(
                    f"evidence: {indicator.evidence}"
                )

            findings.append(
                self.create_finding(
                    title=metadata["title"],
                    severity=metadata["severity"],
                    confidence=metadata["confidence"],
                    target=target,
                    endpoint=endpoint,
                    parameter=parameter,
                    description=metadata["description"],
                    evidence="; ".join(evidence),
                    remediation=self.REMEDIATION,
                    cwe="CWE-89",
                    owasp="A03:2021",
                )
            )

        return findings
