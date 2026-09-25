import pytest

from m_hunter.analyzers.sqli import (
    SQLiAnalysis,
    SQLiIndicator,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.sqli import (
    SQLiValidationResult,
    SQLiValidator,
)


def response(
    content: bytes,
    *,
    status_code: int = 200,
) -> HttpResponse:
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/search",
        headers={"content-type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def analysis(
    category: str = "mysql",
) -> SQLiAnalysis:
    return SQLiAnalysis(
        indicators=[
            SQLiIndicator(
                name=f"{category}_error",
                category=category,
                evidence="SQL database error",
                position=0,
            )
        ]
    )


class TestSQLiValidator:
    def test_validator_creation(self):
        assert SQLiValidator() is not None

    def test_invalid_baseline(self):
        with pytest.raises(TypeError):
            SQLiValidator().validate(
                "invalid",
                response(b"safe"),
                analysis(),
            )

    def test_invalid_candidate(self):
        with pytest.raises(TypeError):
            SQLiValidator().validate(
                response(b"safe"),
                "invalid",
                analysis(),
            )

    def test_invalid_analysis(self):
        with pytest.raises(TypeError):
            SQLiValidator().validate(
                response(b"safe"),
                response(b"safe"),
                "invalid",
            )

    def test_no_indicator(self):
        result = SQLiValidator().validate(
            response(b"safe"),
            response(b"safe"),
            SQLiAnalysis(),
        )

        assert isinstance(result, SQLiValidationResult)
        assert result.status == "no_indicator"
        assert result.potential_sqli is False

    def test_error_indicator_without_behavior_change(self):
        result = SQLiValidator().validate(
            response(b"safe"),
            response(b"SQL database error"),
            analysis(),
        )

        assert result.error_indicator_changed is True
        assert result.response_changed is True
        assert result.potential_sqli is True

    def test_status_change_is_detected(self):
        result = SQLiValidator().validate(
            response(b"safe", status_code=200),
            response(b"SQL error", status_code=500),
            analysis(),
        )

        assert result.status_changed is True
        assert result.response_changed is True

    def test_content_change_is_detected(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"SQL error"),
            analysis(),
        )

        assert result.content_changed is True
        assert result.response_changed is True

    def test_content_length_change_is_detected(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"SQL database error"),
            analysis(),
        )

        assert any(
            "content length changed" in item
            for item in result.evidence
        )

    def test_mysql_category_is_recorded(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"MySQL SQL error"),
            analysis("mysql"),
        )

        assert "mysql" in result.analysis.categories
        assert any(
            "database category: mysql" in item
            for item in result.evidence
        )

    def test_postgresql_category_is_recorded(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"PostgreSQL error"),
            analysis("postgresql"),
        )

        assert "postgresql" in result.analysis.categories

    def test_oracle_category_is_recorded(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"ORA-00942"),
            analysis("oracle"),
        )

        assert "oracle" in result.analysis.categories

    def test_mssql_category_is_recorded(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"SQL Server error"),
            analysis("mssql"),
        )

        assert "mssql" in result.analysis.categories

    def test_sqlite_category_is_recorded(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"SQLite error"),
            analysis("sqlite"),
        )

        assert "sqlite" in result.analysis.categories

    def test_potential_sqli_requires_error_indicator(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"completely different response"),
            SQLiAnalysis(),
        )

        assert result.response_changed is True
        assert result.potential_sqli is False
        assert result.status == "no_indicator"

    def test_potential_sqli_requires_response_change(self):
        same = response(b"SQL database error")

        result = SQLiValidator().validate(
            same,
            same,
            analysis(),
        )

        assert result.error_indicator_changed is True
        assert result.response_changed is False
        assert result.potential_sqli is False

    def test_potential_sqli_requires_both_signals(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"SQL database error"),
            analysis(),
        )

        assert result.potential_sqli is True
        assert result.status == "potential_sqli"

    def test_evidence_is_tuple(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"SQL database error"),
            analysis(),
        )

        assert isinstance(result.evidence, tuple)

    def test_baseline_is_preserved(self):
        baseline = response(b"normal")

        result = SQLiValidator().validate(
            baseline,
            response(b"SQL error"),
            analysis(),
        )

        assert result.baseline is baseline

    def test_candidate_is_preserved(self):
        candidate = response(b"SQL error")

        result = SQLiValidator().validate(
            response(b"normal"),
            candidate,
            analysis(),
        )

        assert result.candidate is candidate

    def test_analysis_is_preserved(self):
        current_analysis = analysis()

        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"SQL error"),
            current_analysis,
        )

        assert result.analysis is current_analysis

    def test_validator_does_not_claim_confirmed_exploitation(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"SQL database error"),
            analysis(),
        )

        assert result.potential_sqli is True
        assert result.status == "potential_sqli"
        assert "exploitation" not in result.status
        assert "confirmed" not in result.status

    def test_error_indicator_count_is_recorded(self):
        result = SQLiValidator().validate(
            response(b"normal"),
            response(b"SQL error"),
            analysis(),
        )

        assert any(
            "SQL error indicators detected: 1" in item
            for item in result.evidence
        )
