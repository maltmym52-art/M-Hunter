import pytest

from m_hunter.analyzers.ssrf import (
    SSRFAnalysis,
    SSRFAnalyzer,
    SSRFIndicatorType,
)
from m_hunter.core.response import HttpResponse


def response(content: bytes) -> HttpResponse:
    return HttpResponse(
        status_code=200,
        url="https://example.com/fetch",
        headers={"content-type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


class TestSSRFAnalyzer:
    def test_analyzer_creation(self):
        assert SSRFAnalyzer() is not None

    def test_invalid_response(self):
        with pytest.raises(TypeError):
            SSRFAnalyzer().analyze("invalid")

    def test_no_indicators(self):
        result = SSRFAnalyzer().analyze(
            response(b"<html>normal response</html>")
        )

        assert isinstance(result, SSRFAnalysis)
        assert result.detected is False
        assert result.indicator_count == 0

    def test_loopback_ip(self):
        result = SSRFAnalyzer().analyze(
            response(b"Request resolved to 127.0.0.1")
        )

        assert result.detected is True
        assert SSRFIndicatorType.INTERNAL_IP in result.types

    def test_private_10_network(self):
        result = SSRFAnalyzer().analyze(
            response(b"upstream: 10.0.0.5")
        )

        assert SSRFIndicatorType.INTERNAL_IP in result.types

    def test_private_192_network(self):
        result = SSRFAnalyzer().analyze(
            response(b"upstream: 192.168.1.10")
        )

        assert SSRFIndicatorType.INTERNAL_IP in result.types

    def test_private_172_network(self):
        result = SSRFAnalyzer().analyze(
            response(b"upstream: 172.16.0.10")
        )

        assert SSRFIndicatorType.INTERNAL_IP in result.types

    def test_link_local_network(self):
        result = SSRFAnalyzer().analyze(
            response(b"upstream: 169.254.1.10")
        )

        assert SSRFIndicatorType.INTERNAL_IP in result.types

    def test_localhost_hostname(self):
        result = SSRFAnalyzer().analyze(
            response(b"resolved host: localhost")
        )

        assert SSRFIndicatorType.INTERNAL_HOSTNAME in result.types

    def test_internal_hostname(self):
        result = SSRFAnalyzer().analyze(
            response(b"resolved host: internal")
        )

        assert SSRFIndicatorType.INTERNAL_HOSTNAME in result.types

    def test_intranet_hostname(self):
        result = SSRFAnalyzer().analyze(
            response(b"resolved host: intranet")
        )

        assert SSRFIndicatorType.INTERNAL_HOSTNAME in result.types

    def test_aws_metadata_address(self):
        result = SSRFAnalyzer().analyze(
            response(b"http://169.254.169.254/latest/meta-data/")
        )

        assert SSRFIndicatorType.CLOUD_METADATA in result.types

    def test_google_metadata_hostname(self):
        result = SSRFAnalyzer().analyze(
            response(b"metadata.google.internal")
        )

        assert SSRFIndicatorType.CLOUD_METADATA in result.types

    def test_google_metadata_api(self):
        result = SSRFAnalyzer().analyze(
            response(b"metadata.googleapis.com")
        )

        assert SSRFIndicatorType.CLOUD_METADATA in result.types

    def test_metadata_path(self):
        result = SSRFAnalyzer().analyze(
            response(b"/latest/meta-data/iam/")
        )

        assert SSRFIndicatorType.CLOUD_METADATA in result.types

    def test_file_scheme(self):
        result = SSRFAnalyzer().analyze(
            response(b"file:///etc/passwd")
        )

        assert SSRFIndicatorType.LOCAL_FILE in result.types

    def test_indicator_evidence_is_preserved(self):
        result = SSRFAnalyzer().analyze(
            response(b"upstream=127.0.0.1")
        )

        assert result.indicators[0].evidence == "127.0.0.1"

    def test_indicator_position_is_preserved(self):
        content = b"prefix upstream=127.0.0.1"

        result = SSRFAnalyzer().analyze(response(content))

        assert result.indicators[0].position == content.index(
            b"127.0.0.1"
        )

    def test_multiple_indicator_types(self):
        result = SSRFAnalyzer().analyze(
            response(
                b"127.0.0.1 "
                b"localhost "
                b"169.254.169.254 "
                b"file:///etc/passwd"
            )
        )

        assert result.indicator_count >= 4
        assert SSRFIndicatorType.INTERNAL_IP in result.types
        assert SSRFIndicatorType.INTERNAL_HOSTNAME in result.types
        assert SSRFIndicatorType.CLOUD_METADATA in result.types
        assert SSRFIndicatorType.LOCAL_FILE in result.types

    def test_types_are_unique(self):
        result = SSRFAnalyzer().analyze(
            response(
                b"127.0.0.1 127.0.0.2 127.0.0.3"
            )
        )

        assert result.types == (
            SSRFIndicatorType.INTERNAL_IP,
        )

    def test_normal_public_ip_is_not_internal(self):
        result = SSRFAnalyzer().analyze(
            response(b"8.8.8.8")
        )

        assert result.detected is False

    def test_normal_hostname_is_not_internal(self):
        result = SSRFAnalyzer().analyze(
            response(b"example.com")
        )

        assert result.detected is False

    def test_detection_does_not_prove_ssrf(self):
        result = SSRFAnalyzer().analyze(
            response(b"localhost")
        )

        assert result.detected is True
        assert result.indicator_count >= 1

    def test_empty_response(self):
        result = SSRFAnalyzer().analyze(response(b""))

        assert result.detected is False
        assert result.indicators == []
