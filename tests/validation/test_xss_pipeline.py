import pytest

from m_hunter.analyzers.xss import XSSAnalysis, XSSContext, XSSReflection
from m_hunter.analyzers.xss_finding import XSSFindingAnalyzer
from m_hunter.core.response import HttpResponse
from m_hunter.validation.xss import XSSValidator
from m_hunter.validation.xss_pipeline import XSSPipeline, XSSPipelineResult


def response(content: bytes) -> HttpResponse:
    return HttpResponse(
        status_code=200,
        url="https://example.com/search",
        headers={"content-type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def analysis(
    context: XSSContext = XSSContext.HTML_TEXT,
) -> XSSAnalysis:
    return XSSAnalysis(
        marker="M-HUNTER",
        reflected=True,
        reflections=[
            XSSReflection(
                value="M-HUNTER",
                context=context,
                position=6,
            )
        ],
    )


class TestXSSPipeline:
    def test_pipeline_creation(self):
        assert XSSPipeline() is not None

    def test_default_dependencies_are_created(self):
        pipeline = XSSPipeline()

        assert isinstance(pipeline.validator, XSSValidator)
        assert isinstance(
            pipeline.finding_analyzer,
            XSSFindingAnalyzer,
        )

    def test_custom_dependencies_are_preserved(self):
        validator = XSSValidator()
        finding_analyzer = XSSFindingAnalyzer()

        pipeline = XSSPipeline(
            validator=validator,
            finding_analyzer=finding_analyzer,
        )

        assert pipeline.validator is validator
        assert pipeline.finding_analyzer is finding_analyzer

    def test_process_returns_pipeline_result(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
            target="https://example.com",
        )

        assert isinstance(result, XSSPipelineResult)

    def test_validation_is_preserved(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
            target="https://example.com",
        )

        assert result.validation.analysis.marker == "M-HUNTER"

    def test_reflection_generates_finding(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
            target="https://example.com",
            endpoint="/search",
            parameter="q",
        )

        assert result.has_findings is True
        assert result.finding_count == 1

    def test_finding_contains_target_context(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
            target="https://example.com",
            endpoint="/search",
            parameter="q",
        )

        finding = result.findings[0]

        assert finding.target == "https://example.com"
        assert finding.endpoint == "/search"
        assert finding.parameter == "q"

    def test_no_reflection_produces_no_finding(self):
        pipeline = XSSPipeline()

        no_reflection = XSSAnalysis(
            marker="M-HUNTER",
            reflected=False,
            reflections=[],
        )

        result = pipeline.process(
            response(b"safe"),
            response(b"safe"),
            no_reflection,
            target="https://example.com",
        )

        assert result.has_findings is False
        assert result.finding_count == 0

    def test_javascript_context_is_preserved(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b"safe"),
            response(b"<script>M-HUNTER</script>"),
            analysis(XSSContext.JAVASCRIPT),
            target="https://example.com",
        )

        assert result.validation.potential_xss is True
        assert result.findings[0].severity == "High"

    def test_json_reflection_stays_non_executable(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b'{"value":"safe"}'),
            response(b'{"value":"M-HUNTER"}'),
            analysis(XSSContext.JSON),
            target="https://example.com",
        )

        assert result.validation.potential_xss is False
        assert result.validation.confirmed_execution is False
        assert result.findings[0].severity == "Low"

    def test_execution_evidence_is_preserved(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
            target="https://example.com",
            execution_evidence=True,
        )

        assert result.validation.confirmed_execution is True
        assert result.validation.status == "execution_evidence"

    def test_pipeline_does_not_infer_execution(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b"safe"),
            response(b"<script>M-HUNTER</script>"),
            analysis(XSSContext.JAVASCRIPT),
            target="https://example.com",
        )

        assert result.validation.confirmed_execution is False
        assert result.validation.status == "potential_xss"

    def test_findings_are_tuple(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
            target="https://example.com",
        )

        assert isinstance(result.findings, tuple)

    def test_result_finding_count(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
            target="https://example.com",
        )

        assert result.finding_count == len(result.findings)

    def test_result_has_findings_property(self):
        pipeline = XSSPipeline()

        result = pipeline.process(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
            target="https://example.com",
        )

        assert result.has_findings is True

    def test_invalid_baseline_is_rejected(self):
        pipeline = XSSPipeline()

        with pytest.raises(TypeError):
            pipeline.process(
                "invalid",
                response(b"M-HUNTER"),
                analysis(),
                target="https://example.com",
            )

    def test_invalid_analysis_is_rejected(self):
        pipeline = XSSPipeline()

        with pytest.raises(TypeError):
            pipeline.process(
                response(b"safe"),
                response(b"M-HUNTER"),
                "invalid",
                target="https://example.com",
            )
