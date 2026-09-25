import pytest

from m_hunter.analyzers.sqli import (
    SQLiAnalysis,
    SQLiIndicator,
)
from m_hunter.analyzers.sqli_finding import SQLiFindingAnalyzer


def indicator(
    category: str,
    evidence: str,
) -> SQLiIndicator:
    return SQLiIndicator(
        name=f"{category}_error",
        category=category,
        evidence=evidence,
        position=0,
    )


class TestSQLiFindingAnalyzer:
    def test_analyzer_creation(self):
        assert SQLiFindingAnalyzer() is not None

    def test_invalid_analysis(self):
        analyzer = SQLiFindingAnalyzer()

        with pytest.raises(TypeError):
            analyzer.analyze(
                "invalid",
                target="https://example.com",
            )

    def test_empty_analysis_returns_no_findings(self):
        analyzer = SQLiFindingAnalyzer()

        result = analyzer.analyze(
            SQLiAnalysis(),
            target="https://example.com",
        )

        assert result == []

    def test_mysql_finding(self):
        analyzer = SQLiFindingAnalyzer()

        result = analyzer.analyze(
            SQLiAnalysis(
                indicators=[
                    indicator(
                        "mysql",
                        "You have an error in your SQL syntax",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert len(result) == 1
        assert result[0].title == "MySQL Error Disclosure"
        assert result[0].severity == "Medium"
        assert result[0].confidence == "Medium"

    def test_postgresql_finding(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[
                    indicator(
                        "postgresql",
                        "PostgreSQL ERROR",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].title == "PostgreSQL Error Disclosure"

    def test_mssql_finding(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[
                    indicator(
                        "mssql",
                        "Microsoft SQL Server",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].title == (
            "Microsoft SQL Server Error Disclosure"
        )

    def test_oracle_finding(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[
                    indicator(
                        "oracle",
                        "ORA-00942",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].title == "Oracle Database Error Disclosure"

    def test_sqlite_finding(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[
                    indicator(
                        "sqlite",
                        "SQLite error",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].title == "SQLite Error Disclosure"

    def test_generic_finding(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[
                    indicator(
                        "generic",
                        "database error",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].title == "SQL Database Error Disclosure"
        assert result[0].severity == "Low"
        assert result[0].confidence == "Low"

    def test_target_is_preserved(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[indicator("mysql", "SQL syntax error")]
            ),
            target="https://example.com",
        )

        assert result[0].target == "https://example.com"

    def test_endpoint_and_parameter_are_preserved(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[indicator("mysql", "SQL syntax error")]
            ),
            target="https://example.com",
            endpoint="/search",
            parameter="q",
        )

        assert result[0].endpoint == "/search"
        assert result[0].parameter == "q"

    def test_database_metadata_is_present(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[indicator("oracle", "ORA-00942")]
            ),
            target="https://example.com",
        )

        finding = result[0]

        assert finding.cwe == "CWE-89"
        assert finding.owasp == "A03:2021"

    def test_evidence_contains_database_category(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[indicator("mysql", "SQL syntax error")]
            ),
            target="https://example.com",
        )

        assert "database category: mysql" in result[0].evidence

    def test_evidence_contains_original_indicator(self):
        evidence = "You have an error in your SQL syntax"

        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[indicator("mysql", evidence)]
            ),
            target="https://example.com",
        )

        assert evidence in result[0].evidence

    def test_multiple_database_categories_create_separate_findings(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[
                    indicator("mysql", "MySQL error"),
                    indicator("postgresql", "PostgreSQL error"),
                ]
            ),
            target="https://example.com",
        )

        assert len(result) == 2

    def test_same_category_is_grouped(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[
                    indicator("oracle", "ORA-00942"),
                    indicator("oracle", "ORA-00933"),
                ]
            ),
            target="https://example.com",
        )

        assert len(result) == 1
        assert "indicator count: 2" in result[0].evidence

    def test_finding_does_not_claim_confirmed_sql_injection(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[
                    indicator("mysql", "SQL syntax error")
                ]
            ),
            target="https://example.com",
        )

        description = result[0].description.lower()

        assert "indicator" in description
        assert "further validation" in description

    def test_remediation_is_present(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[
                    indicator("mysql", "SQL syntax error")
                ]
            ),
            target="https://example.com",
        )

        assert "parameterized queries" in result[0].remediation

    def test_finding_status_defaults_to_open(self):
        result = SQLiFindingAnalyzer().analyze(
            SQLiAnalysis(
                indicators=[
                    indicator("mysql", "SQL syntax error")
                ]
            ),
            target="https://example.com",
        )

        assert result[0].status == "open"
