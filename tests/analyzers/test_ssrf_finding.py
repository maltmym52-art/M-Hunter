import pytest

from m_hunter.analyzers.ssrf import (
    SSRFAnalysis,
    SSRFIndicator,
    SSRFIndicatorType,
)
from m_hunter.analyzers.ssrf_finding import SSRFFindingAnalyzer


def indicator(
    indicator_type: str,
    evidence: str,
) -> SSRFIndicator:
    return SSRFIndicator(
        type=indicator_type,
        evidence=evidence,
        position=0,
    )


class TestSSRFFindingAnalyzer:
    def test_analyzer_creation(self):
        assert SSRFFindingAnalyzer() is not None

    def test_invalid_analysis(self):
        with pytest.raises(TypeError):
            SSRFFindingAnalyzer().analyze(
                "invalid",
                target="https://example.com",
            )

    def test_empty_analysis_returns_no_findings(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(),
            target="https://example.com",
        )

        assert result == []

    def test_internal_ip_finding(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        "10.0.0.5",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert len(result) == 1
        assert result[0].title == (
            "Internal Network Address Indicator"
        )
        assert result[0].severity == "Medium"

    def test_internal_hostname_finding(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_HOSTNAME,
                        "localhost",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].title == "Internal Hostname Indicator"

    def test_loopback_finding(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.LOOPBACK,
                        "127.0.0.1",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].title == "Loopback Address Indicator"
        assert result[0].severity == "High"

    def test_link_local_finding(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.LINK_LOCAL,
                        "169.254.1.1",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].title == "Link-Local Address Indicator"

    def test_cloud_metadata_finding(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.CLOUD_METADATA,
                        "169.254.169.254",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].title == (
            "Cloud Metadata Endpoint Indicator"
        )
        assert result[0].severity == "High"

    def test_local_file_finding(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.LOCAL_FILE,
                        "file:///etc/passwd",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].title == "Local File URI Indicator"

    def test_target_is_preserved(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        "10.0.0.1",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].target == "https://example.com"

    def test_endpoint_and_parameter_are_preserved(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        "10.0.0.1",
                    )
                ]
            ),
            target="https://example.com",
            endpoint="/fetch",
            parameter="url",
        )

        assert result[0].endpoint == "/fetch"
        assert result[0].parameter == "url"

    def test_cwe_and_owasp_metadata(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.CLOUD_METADATA,
                        "metadata.google.internal",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].cwe == "CWE-918"
        assert result[0].owasp == "A10:2021"

    def test_evidence_contains_type(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        "10.0.0.1",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert "indicator type: internal_ip" in result[0].evidence

    def test_evidence_contains_original_value(self):
        value = "127.0.0.1"

        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        value,
                    )
                ]
            ),
            target="https://example.com",
        )

        assert value in result[0].evidence

    def test_same_type_is_grouped(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        "10.0.0.1",
                    ),
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        "192.168.1.1",
                    ),
                ]
            ),
            target="https://example.com",
        )

        assert len(result) == 1
        assert "indicator count: 2" in result[0].evidence

    def test_multiple_types_create_multiple_findings(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        "10.0.0.1",
                    ),
                    indicator(
                        SSRFIndicatorType.CLOUD_METADATA,
                        "169.254.169.254",
                    ),
                ]
            ),
            target="https://example.com",
        )

        assert len(result) == 2

    def test_description_does_not_claim_confirmed_ssrf(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        "10.0.0.1",
                    )
                ]
            ),
            target="https://example.com",
        )

        description = result[0].description.lower()

        assert "indicator" in description
        assert "validation" in description

    def test_remediation_is_present(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        "10.0.0.1",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert "allowlist" in result[0].remediation

    def test_finding_status_defaults_to_open(self):
        result = SSRFFindingAnalyzer().analyze(
            SSRFAnalysis(
                indicators=[
                    indicator(
                        SSRFIndicatorType.INTERNAL_IP,
                        "10.0.0.1",
                    )
                ]
            ),
            target="https://example.com",
        )

        assert result[0].status == "open"
