import pytest

from m_hunter.analyzers.nosql_injection import (
    NoSQLInjectionAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.nosql_injection import (
    NoSQLInjectionValidator,
)


def response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com",
        headers=headers or {"content-type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def injection_analysis():
    return NoSQLInjectionAnalyzer().analyze(
        "https://example.com",
        query={"$ne": "invalid"},
    )


def clean_analysis():
    return NoSQLInjectionAnalyzer().analyze(
        "https://example.com",
        query={"username": "test"},
    )


def test_identical_responses_do_not_confirm_injection():
    result = NoSQLInjectionValidator().compare(
        response(),
        response(),
        injection_analysis(),
    )

    assert result.response_changed is False
    assert result.potential_nosql_injection is False
    assert result.status == "indicator_only"


def test_content_change_is_detected():
    result = NoSQLInjectionValidator().compare(
        response(content=b"normal"),
        response(content=b"changed"),
        injection_analysis(),
    )

    assert result.content_changed is True
    assert result.response_changed is True


def test_content_length_change_is_detected():
    result = NoSQLInjectionValidator().compare(
        response(content=b"abc"),
        response(content=b"abcdef"),
        injection_analysis(),
    )

    assert result.content_length_changed is True


def test_status_change_is_detected():
    result = NoSQLInjectionValidator().compare(
        response(status_code=200),
        response(status_code=500),
        injection_analysis(),
    )

    assert result.status_changed is True
    assert result.response_changed is True


def test_header_change_is_detected():
    result = NoSQLInjectionValidator().compare(
        response(headers={"content-type": "text/html"}),
        response(headers={"content-type": "application/json"}),
        injection_analysis(),
    )

    assert result.headers_changed is True


def test_injection_indicator_is_detected():
    result = NoSQLInjectionValidator().compare(
        response(),
        response(content=b"changed"),
        injection_analysis(),
    )

    assert result.injection_indicator_present is True


def test_clean_analysis_cannot_confirm_injection():
    result = NoSQLInjectionValidator().compare(
        response(),
        response(content=b"changed"),
        clean_analysis(),
    )

    assert result.injection_indicator_present is False
    assert result.potential_nosql_injection is False


def test_operator_plus_response_change_is_potential():
    result = NoSQLInjectionValidator().compare(
        response(content=b"normal"),
        response(content=b"changed"),
        injection_analysis(),
    )

    assert result.potential_nosql_injection is True
    assert result.status == "potential"


def test_baseline_status_is_preserved():
    result = NoSQLInjectionValidator().compare(
        response(status_code=201),
        response(status_code=200),
        injection_analysis(),
    )

    assert result.baseline_status == 201


def test_candidate_status_is_preserved():
    result = NoSQLInjectionValidator().compare(
        response(status_code=200),
        response(status_code=201),
        injection_analysis(),
    )

    assert result.candidate_status == 201


def test_content_evidence_is_reported():
    result = NoSQLInjectionValidator().compare(
        response(content=b"a"),
        response(content=b"b"),
        injection_analysis(),
    )

    assert "Response content changed." in result.evidence


def test_status_evidence_is_reported():
    result = NoSQLInjectionValidator().compare(
        response(status_code=200),
        response(status_code=500),
        injection_analysis(),
    )

    assert any(
        "HTTP status changed" in item
        for item in result.evidence
    )


def test_header_evidence_is_reported():
    result = NoSQLInjectionValidator().compare(
        response(headers={"content-type": "text/html"}),
        response(headers={"content-type": "application/json"}),
        injection_analysis(),
    )

    assert "Relevant response headers changed." in result.evidence


def test_no_indicator_status():
    result = NoSQLInjectionValidator().compare(
        response(),
        response(),
        clean_analysis(),
    )

    assert result.status == "no_indicator"


def test_invalid_baseline_type():
    with pytest.raises(TypeError):
        NoSQLInjectionValidator().compare(
            object(),
            response(),
            injection_analysis(),
        )


def test_invalid_candidate_type():
    with pytest.raises(TypeError):
        NoSQLInjectionValidator().compare(
            response(),
            object(),
            injection_analysis(),
        )


def test_invalid_analysis_type():
    with pytest.raises(TypeError):
        NoSQLInjectionValidator().compare(
            response(),
            response(),
            object(),
        )


def test_regex_indicator_is_supported():
    analysis = NoSQLInjectionAnalyzer().analyze(
        "https://example.com",
        query={"$regex": ".*"},
    )

    result = NoSQLInjectionValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.injection_indicator_present is True
    assert result.potential_nosql_injection is True


def test_javascript_operator_is_supported():
    analysis = NoSQLInjectionAnalyzer().analyze(
        "https://example.com",
        query={"$where": "true"},
    )

    result = NoSQLInjectionValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.injection_indicator_present is True
    assert result.potential_nosql_injection is True


def test_database_error_is_supported():
    analysis = NoSQLInjectionAnalyzer().analyze(
        "https://example.com",
        response_text="MongoServerError",
    )

    result = NoSQLInjectionValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.injection_indicator_present is True


def test_mongodb_context_alone_is_not_confirmation():
    analysis = NoSQLInjectionAnalyzer().analyze(
        "https://example.com",
        response_text="mongoose",
    )

    result = NoSQLInjectionValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.injection_indicator_present is False
    assert result.potential_nosql_injection is False


def test_multiple_changes_are_reported():
    result = NoSQLInjectionValidator().compare(
        response(
            status_code=200,
            content=b"abc",
            headers={"content-type": "text/html"},
        ),
        response(
            status_code=500,
            content=b"abcdef",
            headers={"content-type": "application/json"},
        ),
        injection_analysis(),
    )

    assert result.status_changed is True
    assert result.content_changed is True
    assert result.content_length_changed is True
    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.potential_nosql_injection is True
