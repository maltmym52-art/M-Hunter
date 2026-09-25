import pytest

from m_hunter.analyzers.sqli import SQLiAnalysis, SQLiIndicator
from m_hunter.analyzers.sqli_finding import SQLiFindingAnalyzer
from m_hunter.core.response import HttpResponse
from m_hunter.validation.sqli import SQLiValidator
from m_hunter.validation.sqli_pipeline import (
    SQLiPipeline,
    SQLiPipelineResult,
)


def response(content: bytes, status_code: int = 200) -> HttpResponse:
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/search",
        headers={"content-type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def analysis(category: str = "mysql") -> SQLiAnalysis:
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


class TestSQLiPipeline:
    def test_pipeline_creation(self):
        assert SQLiPipeline() is not None

    def test_default_dependencies(self):
        pipeline = SQLiPipeline()

        assert isinstance(pipeline.validator, SQLiValidator)
        assert isinstance(
            pipeline.finding_analyzer,
            SQLiFindingAnalyzer,
        )

    def test_custom_dependencies(self):
        validator = SQLiValidator()
        finding_analyzer = SQLiFindingAnalyzer()

        pipeline = SQLiPipeline(
            validator=validator,
            finding_analyzer=finding_analyzer,
        )

        assert pipeline.validator is validator
        assert pipeline.finding_analyzer is finding_analyzer

    def test_process_returns_result(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL database error"),
            analysis(),
            target="https://example.com",
        )

        assert isinstance(result, SQLiPipelineResult)

    def test_validation_is_preserved(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL database error"),
            analysis(),
            target="https://example.com",
        )

        assert result.validation.analysis.detected is True
        assert result.validation.potential_sqli is True

    def test_finding_is_generated(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL database error"),
            analysis(),
            target="https://example.com",
        )

        assert result.has_findings is True
        assert result.finding_count == 1

    def test_finding_target_is_preserved(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL database error"),
            analysis(),
            target="https://example.com",
            endpoint="/search",
            parameter="q",
        )

        finding = result.findings[0]

        assert finding.target == "https://example.com"
        assert finding.endpoint == "/search"
        assert finding.parameter == "q"

    def test_no_indicator_produces_no_finding(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"normal"),
            SQLiAnalysis(),
            target="https://example.com",
        )

        assert result.validation.status == "no_indicator"
        assert result.has_findings is False
        assert result.finding_count == 0

    def test_response_change_without_indicator_is_not_sqli(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"different response"),
            SQLiAnalysis(),
            target="https://example.com",
        )

        assert result.validation.response_changed is True
        assert result.validation.potential_sqli is False
        assert result.validation.status == "no_indicator"

    def test_database_error_and_behavior_change_create_potential_sqli(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL database error"),
            analysis(),
            target="https://example.com",
        )

        assert result.validation.potential_sqli is True
        assert result.validation.status == "potential_sqli"

    def test_pipeline_does_not_confirm_exploitation(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL database error"),
            analysis(),
            target="https://example.com",
        )

        assert "confirmed" not in result.validation.status
        assert "exploitation" not in result.validation.status

    def test_postgresql_finding(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"PostgreSQL error"),
            analysis("postgresql"),
            target="https://example.com",
        )

        assert result.findings[0].title == (
            "PostgreSQL Error Disclosure"
        )

    def test_oracle_finding(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"ORA-00942"),
            analysis("oracle"),
            target="https://example.com",
        )

        assert result.findings[0].title == (
            "Oracle Database Error Disclosure"
        )

    def test_multiple_categories_generate_multiple_findings(self):
        current_analysis = SQLiAnalysis(
            indicators=[
                SQLiIndicator(
                    name="mysql_error",
                    category="mysql",
                    evidence="MySQL error",
                    position=0,
                ),
                SQLiIndicator(
                    name="postgresql_error",
                    category="postgresql",
                    evidence="PostgreSQL error",
                    position=0,
                ),
            ]
        )

        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"database errors"),
            current_analysis,
            target="https://example.com",
        )

        assert result.finding_count == 2

    def test_findings_are_tuple(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL error"),
            analysis(),
            target="https://example.com",
        )

        assert isinstance(result.findings, tuple)

    def test_finding_count_matches_findings(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL error"),
            analysis(),
            target="https://example.com",
        )

        assert result.finding_count == len(result.findings)

    def test_has_findings_property(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL error"),
            analysis(),
            target="https://example.com",
        )

        assert result.has_findings is True

    def test_invalid_baseline(self):
        with pytest.raises(TypeError):
            SQLiPipeline().process(
                "invalid",
                response(b"SQL error"),
                analysis(),
                target="https://example.com",
            )

    def test_invalid_candidate(self):
        with pytest.raises(TypeError):
            SQLiPipeline().process(
                response(b"normal"),
                "invalid",
                analysis(),
                target="https://example.com",
            )

    def test_invalid_analysis(self):
        with pytest.raises(TypeError):
            SQLiPipeline().process(
                response(b"normal"),
                response(b"SQL error"),
                "invalid",
                target="https://example.com",
            )

    def test_finding_metadata_is_preserved(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL error"),
            analysis(),
            target="https://example.com",
            endpoint="/search",
            parameter="query",
        )

        finding = result.findings[0]

        assert finding.cwe == "CWE-89"
        assert finding.owasp == "A03:2021"
        assert finding.parameter == "query"

    def test_validation_and_finding_layers_are_separate(self):
        result = SQLiPipeline().process(
            response(b"normal"),
            response(b"SQL error"),
            analysis(),
            target="https://example.com",
        )

        assert result.validation is not None
        assert result.findings is not None
        assert result.validation.potential_sqli is True
        assert result.finding_count == 1
