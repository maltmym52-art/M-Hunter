from m_hunter.analyzers.csrf import (
    CSRFAnalyzer,
    CSRFIndicatorType,
)


def test_state_changing_post_is_detected():
    result = CSRFAnalyzer().analyze("POST")

    assert result.detected
    assert result.state_changing
    assert CSRFIndicatorType.STATE_CHANGING_METHOD in result.types


def test_get_is_not_state_changing():
    result = CSRFAnalyzer().analyze("GET")

    assert not result.state_changing


def test_csrf_token_is_detected():
    result = CSRFAnalyzer().analyze(
        "POST",
        body='<input type="hidden" name="csrf_token" value="abc">',
    )

    assert result.token_present
    assert CSRFIndicatorType.CSRF_TOKEN_PRESENT in result.types


def test_xsrf_token_is_detected():
    result = CSRFAnalyzer().analyze(
        "POST",
        body='<input name="_xsrf_token" value="abc">',
    )

    assert result.token_present


def test_form_without_token_is_detected():
    result = CSRFAnalyzer().analyze(
        "POST",
        body='<form method="post"><input name="email"></form>',
    )

    assert result.missing_token
    assert CSRFIndicatorType.FORM_WITHOUT_CSRF_TOKEN in result.types


def test_put_form_without_token_is_detected():
    result = CSRFAnalyzer().analyze(
        "PUT",
        body='<form method="put"><input name="value"></form>',
    )

    assert result.missing_token


def test_patch_form_without_token_is_detected():
    result = CSRFAnalyzer().analyze(
        "PATCH",
        body='<form method="patch"></form>',
    )

    assert result.missing_token


def test_delete_form_without_token_is_detected():
    result = CSRFAnalyzer().analyze(
        "DELETE",
        body='<form method="delete"></form>',
    )

    assert result.missing_token


def test_state_changing_request_without_body_does_not_claim_missing_token():
    result = CSRFAnalyzer().analyze("POST")

    assert result.state_changing
    assert not result.missing_token


def test_state_changing_body_without_token_is_flagged():
    result = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    assert result.missing_token


def test_same_site_missing_for_session_cookie():
    result = CSRFAnalyzer().analyze(
        "POST",
        cookies={"sessionid": "abc"},
    )

    assert CSRFIndicatorType.SAME_SITE_COOKIE_MISSING in result.types


def test_same_site_metadata_is_not_flagged():
    result = CSRFAnalyzer().analyze(
        "POST",
        cookies={"sessionid": "abc", "SameSite": "Lax"},
    )

    assert CSRFIndicatorType.SAME_SITE_COOKIE_MISSING not in result.types


def test_non_session_cookie_is_ignored_for_samesite():
    result = CSRFAnalyzer().analyze(
        "POST",
        cookies={"analytics": "abc"},
    )

    assert CSRFIndicatorType.SAME_SITE_COOKIE_MISSING not in result.types


def test_origin_missing_is_detected_for_state_change():
    result = CSRFAnalyzer().analyze("POST")

    assert CSRFIndicatorType.ORIGIN_VALIDATION_MISSING in result.types


def test_origin_present_is_not_flagged():
    result = CSRFAnalyzer().analyze(
        "POST",
        headers={"Origin": "https://example.com"},
    )

    assert CSRFIndicatorType.ORIGIN_VALIDATION_MISSING not in result.types


def test_referer_missing_is_detected_for_state_change():
    result = CSRFAnalyzer().analyze("POST")

    assert CSRFIndicatorType.REFERER_VALIDATION_MISSING in result.types


def test_referer_present_is_not_flagged():
    result = CSRFAnalyzer().analyze(
        "POST",
        headers={"Referer": "https://example.com/account"},
    )

    assert CSRFIndicatorType.REFERER_VALIDATION_MISSING not in result.types


def test_header_names_are_case_insensitive():
    result = CSRFAnalyzer().analyze(
        "POST",
        headers={
            "origin": "https://example.com",
            "REFERER": "https://example.com/account",
        },
    )

    assert CSRFIndicatorType.ORIGIN_VALIDATION_MISSING not in result.types
    assert CSRFIndicatorType.REFERER_VALIDATION_MISSING not in result.types


def test_multiple_indicators_are_collected():
    result = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
        cookies={"sessionid": "abc"},
    )

    assert result.indicator_count >= 4
    assert len(result.types) >= 4


def test_indicator_evidence_is_preserved():
    result = CSRFAnalyzer().analyze(
        "POST",
        body='<input name="csrf_token" value="abc">',
    )

    assert result.indicators
    assert all(indicator.evidence for indicator in result.indicators)


def test_analysis_names_match_indicator_types():
    result = CSRFAnalyzer().analyze(
        "POST",
        body="email=test@example.com",
    )

    assert set(result.names) == {
        indicator_type.value for indicator_type in result.types
    }


def test_analysis_without_indicators_is_clean():
    result = CSRFAnalyzer().analyze("GET")

    assert not result.detected
    assert result.indicator_count == 0
    assert result.types == []
    assert result.names == []
