import pytest

from m_hunter.analyzers.ssrf import (
    SSRFAnalysis,
    SSRFIndicator,
    SSRFIndicatorType,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.ssrf import (
    SSRFValidationResult,
    SSRFValidator,
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


class TestSSRFValidator:
    def test_validator_creation(self):
        assert SSRFValidator() is not None

    def test_invalid_baseline(self):
        with pytest.raises(TypeError):
            SSRFValidator().validate(
                "invalid",
                response(b"safe"),
                analysis(),
            )

    def test_invalid_candidate(self):
        with pytest.raises(TypeError):
            SSRFValidator().validate(
                response(b"safe"),
                "invalid",
                analysis(),
            )

    def test_invalid_analysis(self):
        with pytest.raises(TypeError):
            SSRFValidator().validate(
                response(b"safe"),
                response(b"safe"),
                "invalid",
            )

    def test_no_indicator(self):
        result = SSRFValidator().validate(
            response(b"safe"),
            response(b"safe"),
            SSRFAnalysis(),
        )

        assert isinstance(result, SSRFValidationResult)
        assert result.status == "no_indicator"
        assert result.potential_ssrf is False

    def test_indicator_without_response_change_is_not_potential_ssrf(self):
        same = response(b"localhost")

        result = SSRFValidator().validate(
            same,
            same,
            analysis(SSRFIndicatorType.INTERNAL_HOSTNAME),
        )

        assert result.indicator_changed is True
        assert result.response_changed is False
        assert result.potential_ssrf is False
        assert result.status == "indicator_detected"

    def test_indicator_with_content_change_is_potential_ssrf(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"localhost"),
            analysis(SSRFIndicatorType.INTERNAL_HOSTNAME),
        )

        assert result.indicator_changed is True
        assert result.content_changed is True
        assert result.response_changed is True
        assert result.potential_ssrf is True
        assert result.status == "potential_ssrf"

    def test_status_change_is_detected(self):
        result = SSRFValidator().validate(
            response(b"normal", status_code=200),
            response(b"localhost", status_code=500),
            analysis(SSRFIndicatorType.INTERNAL_HOSTNAME),
        )

        assert result.status_changed is True
        assert result.response_changed is True
        assert result.potential_ssrf is True

    def test_content_change_is_detected(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"internal service"),
            SSRFAnalysis(),
        )

        assert result.content_changed is True
        assert result.response_changed is True
        assert result.potential_ssrf is False

    def test_content_length_change_is_detected(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"internal service"),
            analysis(),
        )

        assert result.content_length_changed is True
        assert any(
            "content length changed" in item
            for item in result.evidence
        )

    def test_private_network_indicator(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(SSRFIndicatorType.INTERNAL_IP),
        )

        assert result.potential_ssrf is True
        assert (
            SSRFIndicatorType.INTERNAL_IP
            in result.analysis.types
        )

    def test_cloud_metadata_indicator(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"169.254.169.254"),
            analysis(SSRFIndicatorType.CLOUD_METADATA),
        )

        assert result.potential_ssrf is True
        assert (
            SSRFIndicatorType.CLOUD_METADATA
            in result.analysis.types
        )

    def test_local_file_indicator(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"file:///etc/passwd"),
            analysis(SSRFIndicatorType.LOCAL_FILE),
        )

        assert result.potential_ssrf is True

    def test_loopback_indicator(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"127.0.0.1"),
            analysis(SSRFIndicatorType.LOOPBACK),
        )

        assert result.potential_ssrf is True

    def test_link_local_indicator(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"169.254.1.10"),
            analysis(SSRFIndicatorType.LINK_LOCAL),
        )

        assert result.potential_ssrf is True

    def test_response_change_without_indicator_is_not_ssrf(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"completely different response"),
            SSRFAnalysis(),
        )

        assert result.response_changed is True
        assert result.potential_ssrf is False
        assert result.status == "no_indicator"

    def test_evidence_is_tuple(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"localhost"),
            analysis(SSRFIndicatorType.INTERNAL_HOSTNAME),
        )

        assert isinstance(result.evidence, tuple)

    def test_indicator_count_is_recorded(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"10.0.0.5"),
            analysis(),
        )

        assert any(
            "SSRF indicators detected: 1" in item
            for item in result.evidence
        )

    def test_indicator_type_is_recorded(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"localhost"),
            analysis(SSRFIndicatorType.INTERNAL_HOSTNAME),
        )

        assert any(
            "indicator type: internal_hostname" in item
            for item in result.evidence
        )

    def test_baseline_is_preserved(self):
        baseline = response(b"normal")

        result = SSRFValidator().validate(
            baseline,
            response(b"localhost"),
            analysis(),
        )

        assert result.baseline is baseline

    def test_candidate_is_preserved(self):
        candidate = response(b"localhost")

        result = SSRFValidator().validate(
            response(b"normal"),
            candidate,
            analysis(),
        )

        assert result.candidate is candidate

    def test_analysis_is_preserved(self):
        current_analysis = analysis()

        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"localhost"),
            current_analysis,
        )

        assert result.analysis is current_analysis

    def test_validator_does_not_confirm_ssrf_execution(self):
        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"localhost"),
            analysis(SSRFIndicatorType.INTERNAL_HOSTNAME),
        )

        assert result.potential_ssrf is True
        assert "confirmed" not in result.status
        assert "execution" not in result.status

    def test_multiple_indicator_types_are_preserved(self):
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

        result = SSRFValidator().validate(
            response(b"normal"),
            response(b"internal metadata"),
            current_analysis,
        )

        assert result.potential_ssrf is True
        assert len(result.analysis.types) == 2
