import pytest

from m_hunter.analyzers.ssrf import (
    SSRFAnalysis,
    SSRFIndicator,
    SSRFIndicatorType,
)
from m_hunter.analyzers.ssrf_finding import SSRFFindingAnalyzer
from m_hunter.core.finding import Finding
from m_hunter.core.response import HttpResponse
from m_hunter.validation.ssrf import SSRFValidator
from m_hunter.validation.ssrf_pipeline import (
    SSRFPipeline,
    SSRFPipelineResult,
)


def response(
    content: bytes,
    *,
    status_code: int = 200,
) -> HttpResponse:
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/fetch",
        headers={"content-type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def analysis(
    indicator_type: str = SSRFIndicatorType.INTERNAL_IP,
) -> SSRFAnalysis:
    return SSRFAnalysis(
        indicators=[
            SSRFIndicator(
                type=indicator_type,
                evidence="10.0.0.5",
                position=0,
            )
        ]
    )


class TestSSRFPipeline:
    def test_pipeline_creation(self):
        assert SSRFPipeline() is not None

    def test_default_validator(self):
        pipeline = SSRFPipeline()
        assert isinstance(pipeline.validator, SSRFValidator)

    def test_default_finding_analyzer(self):
        pipeline = SSRFPipeline()
        assert isinstance(
            pipeline.finding_analyzer,
            SSRFFindingAnalyzer,
        )

    def test_result_type(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
            target="https://example.com",
        )

        assert isinstance(result, SSRFPipelineResult)

    def test_pipeline_detects_potential_ssrf(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
            target="https://example.com",
        )

        assert result.potential_ssrf is True
        assert result.status == "potential_ssrf"

    def test_pipeline_generates_findings(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
            target="https://example.com",
        )

        assert result.finding_count == 1
        assert isinstance(result.findings[0], Finding)

    def test_pipeline_preserves_target(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
            target="https://target.example",
        )

        assert result.findings[0].target == "https://target.example"

    def test_pipeline_preserves_endpoint(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
            target="https://target.example",
            endpoint="/fetch",
        )

        assert result.findings[0].endpoint == "/fetch"

    def test_pipeline_preserves_parameter(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
            target="https://target.example",
            parameter="url",
        )

        assert result.findings[0].parameter == "url"

    def test_empty_analysis(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"different"),
            SSRFAnalysis(),
            target="https://example.com",
        )

        assert result.status == "no_indicator"
        assert result.potential_ssrf is False
        assert result.findings == []
        assert result.finding_count == 0

    def test_indicator_without_behavior_change(self):
        same = response(b"10.0.0.5")

        result = SSRFPipeline().run(
            same,
            same,
            analysis(),
            target="https://example.com",
        )

        assert result.status == "indicator_detected"
        assert result.potential_ssrf is False
        assert result.finding_count == 1

    def test_response_change_without_indicator(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"different response"),
            SSRFAnalysis(),
            target="https://example.com",
        )

        assert result.validation.response_changed is True
        assert result.potential_ssrf is False
        assert result.findings == []

    def test_cloud_metadata_pipeline(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"169.254.169.254/latest/meta-data"),
            analysis(SSRFIndicatorType.CLOUD_METADATA),
            target="https://example.com",
        )

        assert result.potential_ssrf is True
        assert result.finding_count == 1
        assert result.findings[0].severity == "High"

    def test_local_file_pipeline(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"file:///etc/passwd"),
            analysis(SSRFIndicatorType.LOCAL_FILE),
            target="https://example.com",
        )

        assert result.potential_ssrf is True
        assert result.finding_count == 1

    def test_multiple_indicator_types_generate_multiple_findings(self):
        current_analysis = SSRFAnalysis(
            indicators=[
                SSRFIndicator(
                    type=SSRFIndicatorType.INTERNAL_IP,
                    evidence="10.0.0.1",
                    position=0,
                ),
                SSRFIndicator(
                    type=SSRFIndicatorType.CLOUD_METADATA,
                    evidence="169.254.169.254",
                    position=10,
                ),
            ]
        )

        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"internal metadata"),
            current_analysis,
            target="https://example.com",
        )

        assert result.potential_ssrf is True
        assert result.finding_count == 2

    def test_validation_is_preserved(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
            target="https://example.com",
        )

        assert result.validation.baseline.status_code == 200
        assert result.validation.candidate.content == b"10.0.0.5"

    def test_findings_are_list(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
            target="https://example.com",
        )

        assert isinstance(result.findings, list)

    def test_invalid_baseline(self):
        with pytest.raises(TypeError):
            SSRFPipeline().run(
                "invalid",
                response(b"10.0.0.5"),
                analysis(),
                target="https://example.com",
            )

    def test_invalid_candidate(self):
        with pytest.raises(TypeError):
            SSRFPipeline().run(
                response(b"normal"),
                "invalid",
                analysis(),
                target="https://example.com",
            )

    def test_invalid_analysis(self):
        with pytest.raises(TypeError):
            SSRFPipeline().run(
                response(b"normal"),
                response(b"10.0.0.5"),
                "invalid",
                target="https://example.com",
            )

    def test_pipeline_does_not_confirm_execution(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
            target="https://example.com",
        )

        assert result.potential_ssrf is True
        assert "confirmed" not in result.status
        assert "execution" not in result.status

    def test_finding_metadata_is_preserved(self):
        result = SSRFPipeline().run(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
            target="https://example.com",
            endpoint="/proxy",
            parameter="url",
        )

        finding = result.findings[0]

        assert finding.cwe == "CWE-918"
        assert finding.owasp == "A10:2021"
        assert finding.endpoint == "/proxy"
        assert finding.parameter == "url"

    def test_custom_components_are_supported(self):
        validator = SSRFValidator()
        finding_analyzer = SSRFFindingAnalyzer()

        pipeline = SSRFPipeline(
            validator=validator,
            finding_analyzer=finding_analyzer,
        )

        assert pipeline.validator is validator
        assert pipeline.finding_analyzer is finding_analyzer
