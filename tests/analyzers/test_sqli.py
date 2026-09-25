import pytest

from m_hunter.analyzers.sqli import SQLiAnalyzer, SQLiAnalysis
from m_hunter.core.response import HttpResponse


def response(content: bytes) -> HttpResponse:
    return HttpResponse(
        status_code=500,
        url="https://example.com/search",
        headers={"content-type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


class TestSQLiAnalyzer:
    def test_analyzer_creation(self):
        assert SQLiAnalyzer() is not None

    def test_invalid_response(self):
        analyzer = SQLiAnalyzer()

        with pytest.raises(TypeError):
            analyzer.analyze("invalid")

    def test_no_indicator(self):
        analyzer = SQLiAnalyzer()

        result = analyzer.analyze(
            response(b"<html>Normal response</html>")
        )

        assert isinstance(result, SQLiAnalysis)
        assert result.detected is False
        assert result.indicator_count == 0

    def test_mysql_error(self):
        result = SQLiAnalyzer().analyze(
            response(
                b"You have an error in your SQL syntax; "
                b"check the manual for your MySQL server version"
            )
        )

        assert result.detected is True
        assert "mysql" in result.categories

    def test_postgresql_error(self):
        result = SQLiAnalyzer().analyze(
            response(
                b"PostgreSQL query failed: "
                b"ERROR: syntax error at or near"
            )
        )

        assert result.detected is True
        assert "postgresql" in result.categories

    def test_mssql_error(self):
        result = SQLiAnalyzer().analyze(
            response(
                b"Microsoft SQL Server Native Client error"
            )
        )

        assert result.detected is True
        assert "mssql" in result.categories

    def test_oracle_error(self):
        result = SQLiAnalyzer().analyze(
            response(b"ORA-00933: SQL command not properly ended")
        )

        assert result.detected is True
        assert "oracle" in result.categories

    def test_sqlite_error(self):
        result = SQLiAnalyzer().analyze(
            response(b"SQLite3.OperationalError: no such table: users")
        )

        assert result.detected is True
        assert "sqlite" in result.categories

    def test_generic_sql_error(self):
        result = SQLiAnalyzer().analyze(
            response(b"Database error: SQL syntax error")
        )

        assert result.detected is True
        assert "generic" in result.categories

    def test_case_insensitive_detection(self):
        result = SQLiAnalyzer().analyze(
            response(b"YOU HAVE AN ERROR IN YOUR SQL SYNTAX")
        )

        assert result.detected is True

    def test_multiple_database_indicators(self):
        result = SQLiAnalyzer().analyze(
            response(
                b"MySQL server version error. "
                b"Also PostgreSQL ERROR detected."
            )
        )

        assert result.indicator_count >= 2
        assert "mysql" in result.categories
        assert "postgresql" in result.categories

    def test_indicator_contains_evidence(self):
        result = SQLiAnalyzer().analyze(
            response(b"ORA-00942: table or view does not exist")
        )

        assert result.indicators[0].evidence
        assert "ORA-00942" in result.indicators[0].evidence

    def test_indicator_contains_position(self):
        content = b"prefix " + b"ORA-00942: table or view does not exist"

        result = SQLiAnalyzer().analyze(response(content))

        assert result.indicators[0].position == 7

    def test_names_are_unique(self):
        result = SQLiAnalyzer().analyze(
            response(
                b"ORA-00942 ORA-00933"
            )
        )

        assert result.names == ("oracle_error",)

    def test_categories_are_unique(self):
        result = SQLiAnalyzer().analyze(
            response(
                b"ORA-00942 ORA-00933"
            )
        )

        assert result.categories == ("oracle",)

    def test_clean_response_with_sql_words_is_not_enough(self):
        result = SQLiAnalyzer().analyze(
            response(
                b"The application uses SQL databases "
                b"for normal data storage."
            )
        )

        assert result.detected is False

    def test_html_content_is_supported(self):
        result = SQLiAnalyzer().analyze(
            response(
                b"<html><body>SQLite error: malformed schema</body></html>"
            )
        )

        assert result.detected is True

    def test_indicator_model_values(self):
        result = SQLiAnalyzer().analyze(
            response(b"SQLSTATE[42000]: database error")
        )

        indicator = result.indicators[0]

        assert indicator.name == "generic_error"
        assert indicator.category == "generic"
        assert indicator.evidence
        assert indicator.position >= 0

    def test_reflection_alone_is_not_detected_as_sql_error(self):
        result = SQLiAnalyzer().analyze(
            response(b"<html>M-HUNTER</html>")
        )

        assert result.detected is False

    def test_empty_response(self):
        result = SQLiAnalyzer().analyze(response(b""))

        assert result.detected is False
        assert result.indicators == []
