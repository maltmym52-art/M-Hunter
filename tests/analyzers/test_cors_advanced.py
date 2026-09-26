import pytest

from m_hunter.analyzers.cors_advanced import (
    CORSAdvancedAnalysis,
    CORSAdvancedAnalyzer,
    CORSAdvancedIndicatorType,
)
from m_hunter.core.response import HttpResponse


def make_response(
    *,
    headers=None,
    status_code=200,
    content=b"OK",
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/api",
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def analyzer():
    return CORSAdvancedAnalyzer()


def test_empty_response(analyzer):
    result = analyzer.analyze(
        make_response()
    )

    assert isinstance(result, CORSAdvancedAnalysis)
    assert result.detected is False
    assert result.count == 0
    assert result.types == ()


def test_requires_http_response(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze("invalid")


def test_allow_origin_is_detected(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin":
                    "https://client.example"
            }
        )
    )

    assert result.detected
    assert result.has_type(
        CORSAdvancedIndicatorType.ACCESS_CONTROL_ALLOW_ORIGIN_PRESENT
    )


def test_credentials_header_is_detected(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Credentials": "true"
            }
        )
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.ACCESS_CONTROL_ALLOW_CREDENTIALS_PRESENT
    )
    assert result.has_type(
        CORSAdvancedIndicatorType.CREDENTIALS_ENABLED
    )


def test_wildcard_credentials(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.WILDCARD_CREDENTIALS
    )


def test_origin_reflection(analyzer):
    origin = "https://attacker.example"

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": origin,
            }
        ),
        origin=origin,
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.ORIGIN_REFLECTION
    )


def test_credentialed_origin_reflection(analyzer):
    origin = "https://attacker.example"

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        ),
        origin=origin,
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.ORIGIN_REFLECTION
    )
    assert result.has_type(
        CORSAdvancedIndicatorType.CREDENTIALED_ORIGIN_REFLECTION
    )


def test_null_origin_reflection(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": "null",
            }
        ),
        origin="null",
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.NULL_ORIGIN_REFLECTION
    )


def test_candidate_origin_with_wildcard(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": "*"
            }
        ),
        origin="https://attacker.example",
        candidate_origin="https://attacker.example",
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.REFLECTED_ARBITRARY_ORIGIN
    )


def test_no_reflection_for_different_origin(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin":
                    "https://trusted.example"
            }
        ),
        origin="https://attacker.example",
    )

    assert not result.has_type(
        CORSAdvancedIndicatorType.ORIGIN_REFLECTION
    )


def test_origin_change_from_baseline(analyzer):
    origin = "https://attacker.example"

    baseline = make_response(
        headers={
            "Access-Control-Allow-Origin":
                "https://trusted.example"
        }
    )

    candidate = make_response(
        headers={
            "Access-Control-Allow-Origin": origin
        }
    )

    result = analyzer.analyze(
        candidate,
        origin=origin,
        baseline=baseline,
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.ORIGIN_REFLECTION
    )


def test_vary_origin_missing(analyzer):
    origin = "https://attacker.example"

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": origin,
            }
        ),
        origin=origin,
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.VARY_ORIGIN_MISSING
    )


def test_vary_origin_present_is_not_flagged(analyzer):
    origin = "https://attacker.example"

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": origin,
                "Vary": "Origin",
            }
        ),
        origin=origin,
    )

    assert not result.has_type(
        CORSAdvancedIndicatorType.VARY_ORIGIN_MISSING
    )


def test_subdomain_trust(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin":
                    "https://example.com"
            }
        ),
        origin="https://sub.example.com",
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.SUBDOMAIN_TRUST
    )


def test_unrelated_origin_not_subdomain_trust(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin":
                    "https://example.com"
            }
        ),
        origin="https://evil.example",
    )

    assert not result.has_type(
        CORSAdvancedIndicatorType.SUBDOMAIN_TRUST
    )


def test_prefix_trust(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin":
                    "https://trusted.example*"
            }
        ),
        origin="https://trusted.example.attacker",
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.PREFIX_TRUST
    )


def test_suffix_trust(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin":
                    "*example.com"
            }
        ),
        origin="https://attackerexample.com",
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.SUFFIX_TRUST
    )


def test_preflight_methods(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Methods":
                    "GET, POST, PUT"
            }
        ),
        preflight=True,
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.PREFLIGHT_METHODS
    )


def test_preflight_headers(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Headers":
                    "Authorization, Content-Type"
            }
        ),
        preflight=True,
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.PREFLIGHT_HEADERS
    )


def test_preflight_credentials(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Credentials": "true"
            }
        ),
        preflight=True,
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.PREFLIGHT_CREDENTIALS
    )


def test_preflight_without_headers_has_no_preflight_indicators(
    analyzer,
):
    result = analyzer.analyze(
        make_response(),
        preflight=True,
    )

    assert not result.has_type(
        CORSAdvancedIndicatorType.PREFLIGHT_METHODS
    )
    assert not result.has_type(
        CORSAdvancedIndicatorType.PREFLIGHT_HEADERS
    )


def test_multiple_indicators(analyzer):
    origin = "https://attacker.example"

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        ),
        origin=origin,
        preflight=True,
    )

    assert result.detected
    assert result.count >= 4
    assert len(result.indicators) == result.count


def test_types_are_unique(analyzer):
    origin = "https://attacker.example"

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        ),
        origin=origin,
    )

    assert len(result.types) == len(set(result.types))


def test_names_match_indicator_types(analyzer):
    origin = "https://attacker.example"

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": origin,
            }
        ),
        origin=origin,
    )

    assert result.names
    assert all(
        name in {indicator_type.value for indicator_type in result.types}
        for name in result.names
    )


def test_has_origin_reflection_property(analyzer):
    origin = "https://attacker.example"

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": origin
            }
        ),
        origin=origin,
    )

    assert result.has_origin_reflection is True


def test_no_origin_reflection_property_when_not_reflected(
    analyzer,
):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin":
                    "https://trusted.example"
            }
        ),
        origin="https://attacker.example",
    )

    assert result.has_origin_reflection is False


def test_indicator_value_is_preserved(analyzer):
    origin = "https://attacker.example"

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": origin
            }
        ),
        origin=origin,
    )

    reflection = next(
        indicator
        for indicator in result.indicators
        if indicator.type
        == CORSAdvancedIndicatorType.ORIGIN_REFLECTION
    )

    assert reflection.value == origin


def test_origin_matching_is_trimmed(analyzer):
    origin = " https://attacker.example "

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin":
                    "https://attacker.example"
            }
        ),
        origin=origin,
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.ORIGIN_REFLECTION
    )


def test_credentials_are_case_insensitive(analyzer):
    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Credentials": "TRUE"
            }
        )
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.CREDENTIALS_ENABLED
    )


def test_baseline_must_be_http_response(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            make_response(),
            baseline="invalid",
        )


def test_preflight_flag_does_not_affect_normal_origin_reflection(
    analyzer,
):
    origin = "https://attacker.example"

    result = analyzer.analyze(
        make_response(
            headers={
                "Access-Control-Allow-Origin": origin
            }
        ),
        origin=origin,
        preflight=False,
    )

    assert result.has_type(
        CORSAdvancedIndicatorType.ORIGIN_REFLECTION
    )
