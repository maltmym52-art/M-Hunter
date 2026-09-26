import base64
import json

import pytest

from m_hunter.analyzers.jwt import (
    JWTAnalyzer,
    JWTIndicatorType,
)


def make_jwt(
    *,
    header=None,
    payload=None,
):
    header = header or {"alg": "HS256", "typ": "JWT"}
    payload = payload or {
        "sub": "123",
        "iat": 1000,
        "exp": 2000,
    }

    def encode(data):
        raw = json.dumps(
            data,
            separators=(",", ":"),
        ).encode()

        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{encode(header)}.{encode(payload)}.signature"


@pytest.fixture
def analyzer():
    return JWTAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()

    assert not result.detected
    assert result.count == 0
    assert result.types == set()


def test_jwt_token_detected(analyzer):
    token = make_jwt()

    result = analyzer.analyze(token=token)

    assert result.jwt
    assert result.count >= 1


def test_algorithm_detected(analyzer):
    token = make_jwt()

    result = analyzer.analyze(token=token)

    assert result.algorithm


def test_none_algorithm_detected(analyzer):
    token = make_jwt(
        header={"alg": "none", "typ": "JWT"},
    )

    result = analyzer.analyze(token=token)

    assert result.none_algorithm
    assert result.weak_algorithm


def test_weak_algorithm_detected(analyzer):
    result = analyzer.analyze(
        algorithm="none",
    )

    assert result.weak_algorithm


def test_custom_weak_algorithm_list(analyzer):
    result = analyzer.analyze(
        algorithm="HS128",
        weak_algorithms={"HS128"},
    )

    assert result.weak_algorithm


def test_expiration_present(analyzer):
    token = make_jwt(
        payload={
            "sub": "123",
            "iat": 1000,
            "exp": 2000,
        },
    )

    result = analyzer.analyze(token=token)

    assert not result.missing_expiration


def test_missing_expiration_detected(analyzer):
    token = make_jwt(
        payload={
            "sub": "123",
            "iat": 1000,
        },
    )

    result = analyzer.analyze(token=token)

    assert result.missing_expiration


def test_long_lived_token_detected(analyzer):
    token = make_jwt(
        payload={
            "sub": "123",
            "iat": 1000,
            "exp": 100000,
        },
    )

    result = analyzer.analyze(
        token=token,
        long_lived_threshold=1000,
    )

    assert result.long_lived_token


def test_short_lived_token_not_marked_long_lived(analyzer):
    token = make_jwt(
        payload={
            "sub": "123",
            "iat": 1000,
            "exp": 1100,
        },
    )

    result = analyzer.analyze(
        token=token,
        long_lived_threshold=1000,
    )

    assert not result.long_lived_token


def test_expected_issuer_missing(analyzer):
    token = make_jwt()

    result = analyzer.analyze(
        token=token,
        expected_claims={"iss"},
    )

    assert result.missing_issuer


def test_expected_audience_missing(analyzer):
    token = make_jwt()

    result = analyzer.analyze(
        token=token,
        expected_claims={"aud"},
    )

    assert result.missing_audience


def test_expected_nbf_missing(analyzer):
    token = make_jwt()

    result = analyzer.analyze(
        token=token,
        expected_claims={"nbf"},
    )

    assert result.missing_not_before


def test_expected_iat_missing(analyzer):
    token = make_jwt(
        payload={
            "sub": "123",
            "exp": 2000,
        },
    )

    result = analyzer.analyze(
        token=token,
        expected_claims={"iat"},
    )

    assert result.missing_issued_at


def test_sensitive_password_claim_detected(analyzer):
    token = make_jwt(
        payload={
            "sub": "123",
            "password": "secret",
            "iat": 1000,
            "exp": 2000,
        },
    )

    result = analyzer.analyze(token=token)

    assert result.sensitive_data


def test_sensitive_api_key_claim_detected(analyzer):
    token = make_jwt(
        payload={
            "sub": "123",
            "api_key": "secret",
            "iat": 1000,
            "exp": 2000,
        },
    )

    result = analyzer.analyze(token=token)

    assert result.sensitive_data


def test_jwt_in_url(analyzer):
    token = make_jwt()

    result = analyzer.analyze(
        url=f"https://example.com/callback?token={token}",
    )

    assert result.jwt
    assert result.jwt_in_url


def test_jwt_in_parameter(analyzer):
    token = make_jwt()

    result = analyzer.analyze(
        params={"id_token": token},
    )

    assert result.jwt_in_url


def test_jwt_in_cookie(analyzer):
    token = make_jwt()

    result = analyzer.analyze(
        cookies={"session": token},
    )

    assert result.jwt_in_cookie


def test_jwt_in_authorization_header(analyzer):
    token = make_jwt()

    result = analyzer.analyze(
        headers={"Authorization": f"Bearer {token}"},
    )

    assert result.jwt_in_authorization


def test_non_bearer_authorization_is_not_jwt(analyzer):
    result = analyzer.analyze(
        headers={"Authorization": "Basic abc123"},
    )

    assert not result.jwt_in_authorization


def test_invalid_structure_is_detected(analyzer):
    result = analyzer.analyze(
        token="eyJhbGciOiJIUzI1NiJ9.invalid.invalid",
    )

    assert result.jwt
    assert result.invalid_structure


def test_random_string_is_ignored(analyzer):
    result = analyzer.analyze(
        token="not-a-jwt",
    )

    assert not result.detected


def test_claims_input_is_supported(analyzer):
    result = analyzer.analyze(
        claims={
            "sub": "123",
            "iat": 1000,
            "exp": 2000,
        },
    )

    assert result.jwt
    assert not result.missing_expiration


def test_claims_input_detects_sensitive_data(analyzer):
    result = analyzer.analyze(
        claims={
            "sub": "123",
            "secret": "value",
            "iat": 1000,
            "exp": 2000,
        },
    )

    assert result.sensitive_data


def test_explicit_algorithm_input(analyzer):
    result = analyzer.analyze(
        algorithm="HS256",
    )

    assert result.algorithm


def test_none_algorithm_explicit_input(analyzer):
    result = analyzer.analyze(
        algorithm="none",
    )

    assert result.none_algorithm


def test_names_are_exposed(analyzer):
    result = analyzer.analyze(
        algorithm="HS256",
    )

    assert "alg" in result.names


def test_types_are_unique(analyzer):
    result = analyzer.analyze(
        token=make_jwt(
            header={"alg": "none", "typ": "JWT"},
        ),
        algorithm="none",
    )

    assert JWTIndicatorType.JWT in result.types
    assert JWTIndicatorType.NONE_ALGORITHM in result.types


def test_threshold_must_be_integer(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            long_lived_threshold="100",
        )


def test_threshold_must_not_be_negative(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            long_lived_threshold=-1,
        )


def test_token_must_be_string(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(token=123)


def test_algorithm_must_be_string(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(algorithm=123)


def test_url_must_be_string(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(url=123)


def test_multiple_sources_are_supported(analyzer):
    token = make_jwt()

    result = analyzer.analyze(
        token=token,
        cookies={"jwt": token},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert result.jwt
    assert result.jwt_in_cookie
    assert result.jwt_in_authorization


def test_analysis_contains_evidence(analyzer):
    result = analyzer.analyze(
        algorithm="none",
    )

    assert result.indicators
    assert all(
        indicator.evidence
        for indicator in result.indicators
    )


def test_expected_claims_present_are_not_flagged(analyzer):
    token = make_jwt(
        payload={
            "sub": "123",
            "iss": "issuer",
            "aud": "audience",
            "nbf": 900,
            "iat": 1000,
            "exp": 2000,
        },
    )

    result = analyzer.analyze(
        token=token,
        expected_claims={
            "iss",
            "aud",
            "nbf",
            "iat",
        },
    )

    assert not result.missing_issuer
    assert not result.missing_audience
    assert not result.missing_not_before
    assert not result.missing_issued_at


def test_custom_threshold_zero(analyzer):
    token = make_jwt(
        payload={
            "iat": 1000,
            "exp": 1001,
        },
    )

    result = analyzer.analyze(
        token=token,
        long_lived_threshold=0,
    )

    assert result.long_lived_token
