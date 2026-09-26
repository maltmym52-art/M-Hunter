from m_hunter.analyzers.subdomain_takeover import (
    SubdomainTakeoverAnalyzer,
    SubdomainTakeoverIndicatorType,
)


def test_clean_hostname():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
        resolved=True,
        http_status=200,
        response_body="Normal application",
    )

    assert result.detected is False
    assert result.count == 0


def test_cname_present():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
        cname="target.example.net",
    )

    assert result.has_type(SubdomainTakeoverIndicatorType.CNAME_PRESENT)


def test_external_cname():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
        cname="example.github.io",
    )

    assert result.has_type(SubdomainTakeoverIndicatorType.CNAME_EXTERNAL)


def test_same_domain_cname_is_not_external():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
        cname="service.app.example.com",
    )

    assert result.has_type(SubdomainTakeoverIndicatorType.CNAME_PRESENT)
    assert not result.has_type(SubdomainTakeoverIndicatorType.CNAME_EXTERNAL)


def test_nxdomain():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="old.example.com",
        dns_status="NXDOMAIN",
    )

    assert result.has_type(SubdomainTakeoverIndicatorType.NXDOMAIN)


def test_dns_error():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="old.example.com",
        dns_status="SERVFAIL",
    )

    assert result.has_type(SubdomainTakeoverIndicatorType.DNS_ERROR)


def test_unresolved_target():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="old.example.com",
        resolved=False,
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET
    )


def test_github_fingerprint():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="docs.example.com",
        cname="example.github.io",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT
    )


def test_heroku_fingerprint():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
        cname="example.herokuapp.com",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT
    )


def test_aws_fingerprint():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="assets.example.com",
        cname="bucket.s3.amazonaws.com",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT
    )


def test_azure_fingerprint():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
        cname="example.azurewebsites.net",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT
    )


def test_takeover_signature():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="docs.example.com",
        response_body="There isn't a GitHub Pages site here.",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE
    )


def test_heroku_takeover_signature():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
        response_body="No such app",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE
    )


def test_bucket_signature():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="assets.example.com",
        response_body="The specified bucket does not exist",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE
    )


def test_host_not_found():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="old.example.com",
        response_body="Could not resolve host",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.HOST_NOT_FOUND
    )


def test_resource_not_found():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="old.example.com",
        response_body="Resource not found",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.RESOURCE_NOT_FOUND
    )


def test_service_unavailable():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="old.example.com",
        response_body="Service unavailable",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.SERVICE_UNAVAILABLE
    )


def test_http_404():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="old.example.com",
        http_status=404,
    )

    assert result.has_type(SubdomainTakeoverIndicatorType.HTTP_404)


def test_headers_can_contain_service_fingerprint():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
        http_headers={"server": "cloudfront.net"},
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT
    )


def test_multiple_indicators():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="old.example.com",
        cname="example.github.io",
        dns_status="NXDOMAIN",
        resolved=False,
        http_status=404,
        response_body="There isn't a GitHub Pages site here.",
    )

    assert result.detected
    assert result.count >= 5


def test_case_insensitive_detection():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
        cname="Example.GitHub.IO",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT
    )


def test_indicator_values_preserved():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
        cname="example.github.io",
    )

    indicator = next(
        i
        for i in result.indicators
        if i.type == SubdomainTakeoverIndicatorType.CNAME_PRESENT
    )

    assert indicator.value == "example.github.io"


def test_names_property():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="old.example.com",
        dns_status="NXDOMAIN",
    )

    assert "NXDOMAIN response" in result.names


def test_types_property():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="old.example.com",
        http_status=404,
    )

    assert SubdomainTakeoverIndicatorType.HTTP_404 in result.types


def test_has_type_false_for_missing_indicator():
    result = SubdomainTakeoverAnalyzer().analyze(
        hostname="app.example.com",
    )

    assert result.has_type(
        SubdomainTakeoverIndicatorType.NXDOMAIN
    ) is False
