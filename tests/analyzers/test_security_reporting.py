import pytest

from m_hunter.analyzers.security_reporting import (
    SecurityReportingAnalysis,
    SecurityReportingAnalyzer,
    SecurityReportingIndicator,
    SecurityReportingIndicatorType,
)
from m_hunter.core.response import HttpResponse


def response(
    headers=None,
    *,
    repeated_headers=None,
):
    return HttpResponse(
        status_code=200,
        url="https://example.com",
        headers=headers or {},
        content=b"OK",
        cookies={},
        response_time=0.1,
        content_length=2,
        repeated_headers=repeated_headers or {},
    )


def test_name():
    assert SecurityReportingAnalyzer.name == "security_reporting"


def test_description():
    assert "reporting" in SecurityReportingAnalyzer.description.lower()


def test_analysis_type():
    result = SecurityReportingAnalyzer().analyze(response())

    assert isinstance(result, SecurityReportingAnalysis)


def test_missing_reporting_endpoints():
    result = SecurityReportingAnalyzer().analyze(response())

    assert result.has_type(
        SecurityReportingIndicatorType.REPORTING_ENDPOINTS_MISSING
    )


def test_missing_report_to():
    result = SecurityReportingAnalyzer().analyze(response())

    assert result.has_type(
        SecurityReportingIndicatorType.REPORT_TO_MISSING
    )


def test_reporting_endpoints_present():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Reporting-Endpoints":
                    'default="https://reports.example/report"',
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.REPORTING_ENDPOINTS_PRESENT
    )
    assert result.has_type(
        SecurityReportingIndicatorType.ENDPOINT_PRESENT
    )


def test_reporting_endpoint_url():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Reporting-Endpoints":
                    'default="https://reports.example/report"',
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.REPORTING_ENDPOINT_URL
    )


def test_multiple_reporting_endpoints():
    result = SecurityReportingAnalyzer().analyze(
        response(
            repeated_headers={
                "Reporting-Endpoints": [
                    'default="https://one.example/report"',
                    'errors="https://two.example/report"',
                ]
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.MULTIPLE_REPORTING_ENDPOINTS
    )


def test_invalid_reporting_endpoints():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Reporting-Endpoints": "invalid",
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS
    )


def test_empty_reporting_endpoints():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Reporting-Endpoints": "",
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS
    )


def test_report_to_present():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Report-To": (
                    '{"group":"default",'
                    '"endpoints":[{"url":"https://reports.example"}]}'
                )
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.REPORT_TO_PRESENT
    )


def test_report_to_group():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Report-To": (
                    '{"group":"default",'
                    '"endpoints":[{"url":"https://reports.example"}]}'
                )
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.GROUP_PRESENT
    )


def test_report_to_endpoint():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Report-To": (
                    '{"group":"default",'
                    '"endpoints":[{"url":"https://reports.example"}]}'
                )
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.ENDPOINT_PRESENT
    )


def test_report_to_endpoint_url():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Report-To": (
                    '{"group":"default",'
                    '"endpoints":[{"url":"https://reports.example"}]}'
                )
            }
        )
    )

    indicators = [
        indicator
        for indicator in result.indicators
        if indicator.type
        == SecurityReportingIndicatorType.REPORTING_ENDPOINT_URL
    ]

    assert indicators[0].value == "https://reports.example"


def test_invalid_report_to_json():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Report-To": "{invalid-json",
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.INVALID_REPORT_TO
    )


def test_report_to_non_object():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Report-To": "[]",
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.INVALID_REPORT_TO
    )


def test_report_to_missing_endpoints():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Report-To": '{"group":"default"}',
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.INVALID_REPORT_TO
    )


def test_report_to_invalid_endpoint():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Report-To": (
                    '{"group":"default",'
                    '"endpoints":[{"url":""}]}'
                )
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.INVALID_REPORT_TO
    )


def test_csp_report_only():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Content-Security-Policy-Report-Only":
                    "default-src 'self'; report-uri /csp-report",
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.CSP_REPORT_ONLY
    )


def test_header_names_case_insensitive():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "reporting-endpoints":
                    'default="https://reports.example"',
                "report-to": (
                    '{"group":"default",'
                    '"endpoints":[{"url":"https://reports.example"}]}'
                ),
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.REPORTING_ENDPOINTS_PRESENT
    )
    assert result.has_type(
        SecurityReportingIndicatorType.REPORT_TO_PRESENT
    )


def test_multiple_report_to():
    result = SecurityReportingAnalyzer().analyze(
        response(
            repeated_headers={
                "Report-To": [
                    '{"group":"one","endpoints":[{"url":"https://one.example"}]}',
                    '{"group":"two","endpoints":[{"url":"https://two.example"}]}',
                ]
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.MULTIPLE_REPORT_TO
    )


def test_indicator_properties():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Reporting-Endpoints":
                    'default="https://reports.example"',
            }
        )
    )

    assert result.count > 0
    assert result.types
    assert result.names


def test_indicator_is_frozen():
    indicator = SecurityReportingIndicator(
        type=SecurityReportingIndicatorType.ENDPOINT_PRESENT,
        name="endpoint",
        value="https://example.com",
    )

    with pytest.raises(Exception):
        indicator.value = "changed"


def test_analysis_is_frozen():
    result = SecurityReportingAnalyzer().analyze(response())

    with pytest.raises(Exception):
        result.detected = False


def test_invalid_response_type():
    with pytest.raises(TypeError):
        SecurityReportingAnalyzer().analyze(object())


def test_mixed_reporting_endpoints():
    result = SecurityReportingAnalyzer().analyze(
        response(
            {
                "Reporting-Endpoints":
                    'default="https://one.example", invalid',
            }
        )
    )

    assert result.has_type(
        SecurityReportingIndicatorType.ENDPOINT_PRESENT
    )
    assert result.has_type(
        SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS
    )
