from m_hunter.analyzers.subdomain_takeover import (
    SubdomainTakeoverAnalysis,
    SubdomainTakeoverIndicator,
    SubdomainTakeoverIndicatorType,
)
from m_hunter.validation.subdomain_takeover import (
    SubdomainTakeoverValidator,
)


def analysis(
    *types: SubdomainTakeoverIndicatorType,
) -> SubdomainTakeoverAnalysis:
    indicators = [
        SubdomainTakeoverIndicator(
            type=indicator_type,
            name=indicator_type.value,
            value=indicator_type.value,
        )
        for indicator_type in types
    ]

    return SubdomainTakeoverAnalysis(
        detected=bool(indicators),
        indicators=indicators,
    )


def test_clean():
    result = SubdomainTakeoverValidator().validate(
        analysis(),
    )

    assert result.status == "clean"
    assert result.potential_subdomain_takeover is False


def test_external_cname_only_is_not_potential():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        ),
    )

    assert result.external_cname
    assert result.potential_subdomain_takeover is False
    assert result.status == "indicator"


def test_fingerprint_only_is_not_potential():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
        ),
    )

    assert result.service_fingerprint
    assert result.potential_subdomain_takeover is False


def test_nxdomain_only_is_not_potential():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.NXDOMAIN,
        ),
    )

    assert result.nxdomain
    assert result.potential_subdomain_takeover is False


def test_unresolved_only_is_not_potential():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET,
        ),
    )

    assert result.unresolved_target
    assert result.potential_subdomain_takeover is False


def test_external_cname_plus_nxdomain_without_behavior_change():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.NXDOMAIN,
        ),
    )

    assert result.external_cname
    assert result.nxdomain
    assert result.potential_subdomain_takeover is False


def test_external_cname_plus_unresolved_with_response_change():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET,
        ),
        response_changed=True,
    )

    assert result.potential_subdomain_takeover


def test_external_cname_plus_fingerprint_plus_unresolved():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
            SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET,
        ),
        response_changed=True,
    )

    assert result.potential_subdomain_takeover


def test_external_cname_plus_fingerprint_plus_nxdomain():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
            SubdomainTakeoverIndicatorType.NXDOMAIN,
        ),
        response_changed=True,
    )

    assert result.potential_subdomain_takeover


def test_takeover_signature_plus_external_cname():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
        ),
    )

    assert result.takeover_signature
    assert result.potential_subdomain_takeover


def test_takeover_signature_without_external_cname():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
        ),
    )

    assert result.potential_subdomain_takeover is False


def test_dangling_cname_plus_external_cname():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_DANGLING,
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        ),
    )

    assert result.potential_subdomain_takeover is False


def test_dangling_cname_plus_external_with_response_change():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_DANGLING,
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        ),
        response_changed=True,
    )

    assert result.potential_subdomain_takeover


def test_service_fingerprint_requires_dns_condition():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
        ),
        response_changed=True,
    )

    assert result.potential_subdomain_takeover is False


def test_response_change_is_tracked():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        ),
        response_changed=True,
    )

    assert result.response_changed


def test_dns_target_present_is_tracked():
    result = SubdomainTakeoverValidator().validate(
        analysis(),
        dns_target_present=True,
    )

    assert result.dns_target_present


def test_security_indicator_present():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        ),
    )

    assert result.security_indicator_present


def test_http_404_is_not_enough():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.HTTP_404,
        ),
        response_changed=True,
    )

    assert result.security_indicator_present is False
    assert result.potential_subdomain_takeover is False


def test_dns_error_is_not_enough():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.DNS_ERROR,
        ),
        response_changed=True,
    )

    assert result.security_indicator_present is False
    assert result.potential_subdomain_takeover is False


def test_resource_not_found_can_support_takeover():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.RESOURCE_NOT_FOUND,
        ),
        response_changed=True,
    )

    assert result.security_indicator_present
    assert result.potential_subdomain_takeover is False


def test_host_not_found_can_support_takeover():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.HOST_NOT_FOUND,
        ),
        response_changed=True,
    )

    assert result.security_indicator_present
    assert result.potential_subdomain_takeover is False


def test_evidence_contains_external_cname():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        ),
    )

    assert "external CNAME detected" in result.evidence


def test_evidence_contains_signature():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
        ),
    )

    assert "takeover signature detected" in result.evidence


def test_status_indicator():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        ),
    )

    assert result.status == "indicator"


def test_status_potential():
    result = SubdomainTakeoverValidator().validate(
        analysis(
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
            SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET,
        ),
        response_changed=True,
    )

    assert result.status == "potential"
