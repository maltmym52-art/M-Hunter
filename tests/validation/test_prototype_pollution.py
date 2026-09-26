import pytest

from m_hunter.analyzers.prototype_pollution import (
    PrototypePollutionAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.prototype_pollution import (
    PrototypePollutionValidator,
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


def analysis_with_proto():
    return PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )


def clean_analysis():
    return PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        query={"name": "test"},
    )


def test_identical_responses_do_not_confirm_pollution():
    baseline = response()
    candidate = response()

    result = PrototypePollutionValidator().compare(
        baseline,
        candidate,
        analysis_with_proto(),
    )

    assert result.response_changed is False
    assert result.potential_prototype_pollution is False
    assert result.status == "indicator_only"


def test_content_change_is_detected():
    baseline = response(content=b"normal")
    candidate = response(content=b"changed")

    result = PrototypePollutionValidator().compare(
        baseline,
        candidate,
        analysis_with_proto(),
    )

    assert result.content_changed is True
    assert result.response_changed is True


def test_content_length_change_is_detected():
    baseline = response(content=b"abc")
    candidate = response(content=b"abcdef")

    result = PrototypePollutionValidator().compare(
        baseline,
        candidate,
        analysis_with_proto(),
    )

    assert result.content_length_changed is True


def test_status_change_is_detected():
    baseline = response(status_code=200)
    candidate = response(status_code=500)

    result = PrototypePollutionValidator().compare(
        baseline,
        candidate,
        analysis_with_proto(),
    )

    assert result.status_changed is True
    assert result.response_changed is True


def test_header_change_is_detected():
    baseline = response(
        headers={"content-type": "text/html"},
    )
    candidate = response(
        headers={"content-type": "application/json"},
    )

    result = PrototypePollutionValidator().compare(
        baseline,
        candidate,
        analysis_with_proto(),
    )

    assert result.headers_changed is True


def test_proto_indicator_is_detected():
    result = PrototypePollutionValidator().compare(
        response(),
        response(content=b"changed"),
        analysis_with_proto(),
    )

    assert result.pollution_indicator_present is True


def test_clean_analysis_cannot_confirm_pollution():
    baseline = response()
    candidate = response(content=b"changed")

    result = PrototypePollutionValidator().compare(
        baseline,
        candidate,
        clean_analysis(),
    )

    assert result.pollution_indicator_present is False
    assert result.potential_prototype_pollution is False


def test_proto_plus_response_change_is_potential():
    baseline = response(content=b"normal")
    candidate = response(content=b"polluted")

    result = PrototypePollutionValidator().compare(
        baseline,
        candidate,
        analysis_with_proto(),
    )

    assert result.potential_prototype_pollution is True
    assert result.status == "potential"


def test_baseline_status_is_preserved():
    result = PrototypePollutionValidator().compare(
        response(status_code=201),
        response(status_code=200),
        analysis_with_proto(),
    )

    assert result.baseline_status == 201


def test_candidate_status_is_preserved():
    result = PrototypePollutionValidator().compare(
        response(status_code=200),
        response(status_code=201),
        analysis_with_proto(),
    )

    assert result.candidate_status == 201


def test_evidence_mentions_content_change():
    result = PrototypePollutionValidator().compare(
        response(content=b"a"),
        response(content=b"b"),
        analysis_with_proto(),
    )

    assert "Response content changed." in result.evidence


def test_evidence_mentions_status_change():
    result = PrototypePollutionValidator().compare(
        response(status_code=200),
        response(status_code=500),
        analysis_with_proto(),
    )

    assert any("HTTP status changed" in item for item in result.evidence)


def test_evidence_mentions_headers():
    result = PrototypePollutionValidator().compare(
        response(headers={"content-type": "text/html"}),
        response(headers={"content-type": "application/json"}),
        analysis_with_proto(),
    )

    assert "Relevant response headers changed." in result.evidence


def test_no_indicator_status():
    result = PrototypePollutionValidator().compare(
        response(),
        response(),
        clean_analysis(),
    )

    assert result.status == "no_indicator"


def test_invalid_baseline_type():
    with pytest.raises(TypeError):
        PrototypePollutionValidator().compare(
            object(),
            response(),
            analysis_with_proto(),
        )


def test_invalid_candidate_type():
    with pytest.raises(TypeError):
        PrototypePollutionValidator().compare(
            response(),
            object(),
            analysis_with_proto(),
        )


def test_invalid_analysis_type():
    with pytest.raises(TypeError):
        PrototypePollutionValidator().compare(
            response(),
            response(),
            object(),
        )


def test_constructor_indicator_is_supported():
    analysis = PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        query={"constructor": "prototype"},
    )

    result = PrototypePollutionValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.pollution_indicator_present is True
    assert result.potential_prototype_pollution is True


def test_prototype_indicator_is_supported():
    analysis = PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        query={"prototype": "polluted"},
    )

    result = PrototypePollutionValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.pollution_indicator_present is True
    assert result.potential_prototype_pollution is True


def test_pollution_marker_is_supported():
    analysis = PrototypePollutionAnalyzer().analyze(
        "https://example.com",
        response_text="polluted",
    )

    result = PrototypePollutionValidator().compare(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.pollution_indicator_present is True


def test_response_changed_is_false_when_all_fields_match():
    result = PrototypePollutionValidator().compare(
        response(),
        response(),
        clean_analysis(),
    )

    assert result.response_changed is False


def test_multiple_changes_are_reported():
    result = PrototypePollutionValidator().compare(
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
        analysis_with_proto(),
    )

    assert result.status_changed is True
    assert result.content_changed is True
    assert result.content_length_changed is True
    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.potential_prototype_pollution is True
