import pytest

from m_hunter.analyzers.saml import (
    SAMLAnalysis,
    SAMLAnalyzer,
    SAMLIndicatorType,
)


@pytest.fixture
def analyzer():
    return SAMLAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()

    assert isinstance(result, SAMLAnalysis)
    assert result.detected is False
    assert result.count == 0
    assert result.types == ()
    assert result.names == ()
    assert result.indicators == ()


@pytest.mark.parametrize(
    "kwargs, indicator_type",
    [
        (
            {"saml_response": "encoded-response"},
            SAMLIndicatorType.SAML_RESPONSE,
        ),
        (
            {"relay_state": "relay-value"},
            SAMLIndicatorType.RELAY_STATE,
        ),
        (
            {"issuer": "https://idp.example"},
            SAMLIndicatorType.ISSUER,
        ),
        (
            {"audience": "https://sp.example"},
            SAMLIndicatorType.AUDIENCE,
        ),
        (
            {"destination": "https://sp.example/acs"},
            SAMLIndicatorType.DESTINATION,
        ),
        (
            {"acs_url": "https://sp.example/acs"},
            SAMLIndicatorType.ACS_URL,
        ),
        (
            {"signature": "encoded-signature"},
            SAMLIndicatorType.SIGNATURE,
        ),
        (
            {"signature_algorithm": "rsa-sha256"},
            SAMLIndicatorType.SIGNATURE_ALGORITHM,
        ),
        (
            {"assertion": "encoded-assertion"},
            SAMLIndicatorType.ASSERTION,
        ),
        (
            {"name_id": "user@example.com"},
            SAMLIndicatorType.NAME_ID,
        ),
        (
            {"not_before": "2026-01-01T00:00:00Z"},
            SAMLIndicatorType.NOT_BEFORE,
        ),
        (
            {"not_on_or_after": "2026-01-01T01:00:00Z"},
            SAMLIndicatorType.NOT_ON_OR_AFTER,
        ),
        (
            {"in_response_to": "_request123"},
            SAMLIndicatorType.IN_RESPONSE_TO,
        ),
        (
            {"encryption": "AES256"},
            SAMLIndicatorType.ENCRYPTION,
        ),
    ],
)
def test_individual_indicators(
    analyzer,
    kwargs,
    indicator_type,
):
    result = analyzer.analyze(**kwargs)

    assert result.detected
    assert indicator_type in result.types


def test_query_parameters_are_detected(analyzer):
    result = analyzer.analyze(
        "https://example.com/acs"
        "?SAMLResponse=response"
        "&RelayState=relay"
        "&Issuer=idp"
        "&Audience=sp"
    )

    assert result.has_saml_response
    assert result.has_relay_state
    assert result.has_issuer
    assert result.has_audience


def test_query_parameters_are_case_normalized(analyzer):
    result = analyzer.analyze(
        params={
            "SAMLResponse": "response",
            "RelayState": "relay",
        }
    )

    assert result.has_saml_response
    assert result.has_relay_state


def test_weak_sha1_algorithm_is_detected(analyzer):
    result = analyzer.analyze(
        signature_algorithm="rsa-sha1"
    )

    assert result.has_signature_algorithm
    assert result.has_weak_signature_algorithm


@pytest.mark.parametrize(
    "algorithm",
    [
        "sha1",
        "rsa-sha1",
        "dsa-sha1",
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    ],
)
def test_weak_algorithms(analyzer, algorithm):
    result = analyzer.analyze(
        signature_algorithm=algorithm
    )

    assert result.has_weak_signature_algorithm


def test_strong_algorithm_is_not_flagged_as_weak(analyzer):
    result = analyzer.analyze(
        signature_algorithm="rsa-sha256"
    )

    assert result.has_signature_algorithm
    assert not result.has_weak_signature_algorithm


def test_unsigned_assertion_explicit(analyzer):
    result = analyzer.analyze(
        assertion="assertion-data",
        signed_assertion=False,
    )

    assert result.has_assertion
    assert result.has_unsigned_assertion


def test_unsigned_assertion_inferred(analyzer):
    result = analyzer.analyze(
        assertion="assertion-data",
    )

    assert result.has_assertion
    assert result.has_unsigned_assertion


def test_signed_assertion_is_not_marked_unsigned(analyzer):
    result = analyzer.analyze(
        assertion="assertion-data",
        signature="signature-data",
        signed_assertion=True,
    )

    assert result.has_assertion
    assert result.has_signature
    assert not result.has_unsigned_assertion


def test_body_is_analyzed(analyzer):
    result = analyzer.analyze(
        body=(
            "<Assertion>"
            "<Issuer>idp.example</Issuer>"
            "<Audience>sp.example</Audience>"
            "</Assertion>"
        )
    )

    assert result.has_assertion is False


def test_headers_are_accepted(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        },
        issuer="idp.example",
    )

    assert result.has_issuer


def test_explicit_arguments_override_params(analyzer):
    result = analyzer.analyze(
        params={"issuer": "query-idp"},
        issuer="explicit-idp",
    )

    issuer_indicators = [
        item
        for item in result.indicators
        if item.type == SAMLIndicatorType.ISSUER
    ]

    assert issuer_indicators
    assert issuer_indicators[0].value == "explicit-idp"


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"issuer": "idp"},
    ],
)
def test_valid_params(analyzer, value):
    result = analyzer.analyze(params=value)

    assert isinstance(result, SAMLAnalysis)


@pytest.mark.parametrize(
    "value",
    [
        [],
        "invalid",
        123,
    ],
)
def test_invalid_params_type(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(params=value)


@pytest.mark.parametrize(
    "value",
    [
        [],
        123,
        object(),
    ],
)
def test_invalid_url_type(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(url=value)


@pytest.mark.parametrize(
    "value",
    [
        123,
        [],
        {},
    ],
)
def test_invalid_body_type(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(body=value)


@pytest.mark.parametrize(
    "value",
    [
        123,
        [],
        "invalid",
    ],
)
def test_invalid_headers_type(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(headers=value)


def test_all_indicator_types_have_properties(analyzer):
    result = analyzer.analyze(
        saml_response="response",
        relay_state="relay",
        issuer="issuer",
        audience="audience",
        destination="destination",
        acs_url="acs",
        signature="signature",
        signature_algorithm="rsa-sha256",
        assertion="assertion",
        name_id="name",
        not_before="before",
        not_on_or_after="after",
        in_response_to="request",
        encryption="aes",
    )

    assert result.has_saml_response
    assert result.has_relay_state
    assert result.has_issuer
    assert result.has_audience
    assert result.has_destination
    assert result.has_acs_url
    assert result.has_signature
    assert result.has_signature_algorithm
    assert result.has_assertion
    assert result.has_name_id
    assert result.has_not_before
    assert result.has_not_on_or_after
    assert result.has_in_response_to
    assert result.has_encryption


def test_unique_types_and_names(analyzer):
    result = analyzer.analyze(
        params={
            "issuer": "idp",
        },
        issuer="idp",
    )

    assert result.types.count(
        SAMLIndicatorType.ISSUER
    ) == 1

    assert result.names.count("Issuer") == 1


def test_analysis_is_immutable(analyzer):
    result = analyzer.analyze(
        issuer="idp"
    )

    with pytest.raises(AttributeError):
        result.detected = False


def test_indicator_is_immutable(analyzer):
    result = analyzer.analyze(
        issuer="idp"
    )

    with pytest.raises(AttributeError):
        result.indicators[0].value = "changed"


def test_bytes_body_is_supported(analyzer):
    result = analyzer.analyze(
        body=b"SAMLResponse=encoded"
    )

    assert isinstance(result, SAMLAnalysis)


def test_multiple_indicators_are_detected(analyzer):
    result = analyzer.analyze(
        issuer="idp",
        audience="sp",
        assertion="assertion",
        signature="signature",
        name_id="user",
    )

    assert result.count >= 5
    assert len(result.types) >= 5
    assert result.detected is True
