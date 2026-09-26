from m_hunter.analyzers.subdomain_takeover import (
    SubdomainTakeoverAnalysis,
    SubdomainTakeoverIndicator,
    SubdomainTakeoverIndicatorType,
)
from m_hunter.validation.subdomain_takeover_pipeline import (
    SubdomainTakeoverPipeline,
)


def analysis(*types):
    indicators = [
        SubdomainTakeoverIndicator(
            type=t,
            name=t.value,
            value=t.value,
        )
        for t in types
    ]

    return SubdomainTakeoverAnalysis(
        detected=bool(indicators),
        indicators=indicators,
    )


def test_clean_rejected():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(),
        target="https://example.com",
    )

    assert result.accepted is False
    assert result.findings == []


def test_external_cname_only_rejected():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        ),
        target="https://example.com",
    )

    assert result.accepted is False


def test_unresolved_external_cname_with_change_accepted():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET,
        ),
        target="https://example.com",
        response_changed=True,
    )

    assert result.accepted
    assert result.findings


def test_nxdomain_external_cname_with_change_accepted():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.NXDOMAIN,
        ),
        target="https://example.com",
        response_changed=True,
    )

    assert result.accepted


def test_signature_with_external_cname_accepted():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
        ),
        target="https://example.com",
    )

    assert result.accepted


def test_signature_without_external_cname_rejected():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
        ),
        target="https://example.com",
    )

    assert result.accepted is False


def test_fingerprint_without_dns_failure_rejected():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
        ),
        target="https://example.com",
        response_changed=True,
    )

    assert result.accepted is False


def test_fingerprint_unresolved_with_change_accepted():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
            SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET,
        ),
        target="https://example.com",
        response_changed=True,
    )

    assert result.accepted


def test_404_alone_rejected():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.HTTP_404,
        ),
        target="https://example.com",
        response_changed=True,
    )

    assert result.accepted is False


def test_dns_error_alone_rejected():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.DNS_ERROR,
        ),
        target="https://example.com",
        response_changed=True,
    )

    assert result.accepted is False


def test_findings_preserve_target():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
        ),
        target="https://old.example.com",
    )

    assert result.findings[0].target == "https://old.example.com"


def test_endpoint_preserved():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
        ),
        target="https://old.example.com",
        endpoint="/",
    )

    assert result.findings[0].endpoint == "/"


def test_parameter_preserved():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
        ),
        target="https://old.example.com",
        parameter="host",
    )

    assert result.findings[0].parameter == "host"


def test_multiple_indicators_create_findings():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
        ),
        target="https://old.example.com",
    )

    assert result.accepted
    assert len(result.findings) == 3


def test_validation_exposed():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET,
        ),
        target="https://example.com",
        response_changed=True,
    )

    assert result.validation.potential_subdomain_takeover


def test_dns_target_present_forwarded():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(),
        target="https://example.com",
        dns_target_present=True,
    )

    assert result.validation.dns_target_present


def test_dangling_external_with_change():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_DANGLING,
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        ),
        target="https://example.com",
        response_changed=True,
    )

    assert result.accepted


def test_dangling_without_change_rejected():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_DANGLING,
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        ),
        target="https://example.com",
    )

    assert result.accepted is False


def test_resource_not_found_not_enough():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.RESOURCE_NOT_FOUND,
        ),
        target="https://example.com",
        response_changed=True,
    )

    assert result.accepted is False


def test_host_not_found_not_enough():
    result = SubdomainTakeoverPipeline().run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.HOST_NOT_FOUND,
        ),
        target="https://example.com",
        response_changed=True,
    )

    assert result.accepted is False


def test_pipeline_name():
    assert SubdomainTakeoverPipeline.name == "subdomain_takeover_pipeline"


def test_pipeline_reusable():
    pipeline = SubdomainTakeoverPipeline()

    first = pipeline.run(
        analysis=analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
        ),
        target="https://old.example.com",
    )

    second = pipeline.run(
        analysis=analysis(),
        target="https://safe.example.com",
    )

    assert first.accepted
    assert second.accepted is False
