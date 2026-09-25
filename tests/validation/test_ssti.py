import pytest

from m_hunter.analyzers.ssti import (
    SSTIAnalysis,
    SSTIAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.ssti import (
    SSTIValidationResult,
    SSTIValidator,
)


def response(
    status_code=200,
    content=b"same",
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/render",
        headers={},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def test_no_indicator_status():
    result = SSTIValidator().validate(
        response(),
        response(),
        SSTIAnalysis(),
    )

    assert result.status == "no_indicator"
    assert not result.potential_ssti


def test_indicator_without_response_change():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(),
        response(),
        analysis,
    )

    assert result.status == "indicator_detected"
    assert not result.potential_ssti


def test_response_change_creates_potential_ssti():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.potential_ssti
    assert result.status == "potential_ssti"


def test_status_change_is_detected():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(status_code=200),
        response(status_code=500),
        analysis,
    )

    assert result.status_changed
    assert result.response_changed


def test_content_change_is_detected():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.content_changed
    assert result.response_changed


def test_content_length_change_is_detected():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(content=b"a"),
        response(content=b"abcdef"),
        analysis,
    )

    assert result.content_length_changed


def test_same_responses_have_no_change():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert not result.response_changed
    assert not result.potential_ssti


def test_evaluation_evidence_is_recorded():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(),
        response(),
        analysis,
        evaluation_evidence=True,
    )

    assert result.evaluation_evidence
    assert result.status == "evaluation_evidence"


def test_evaluation_evidence_is_explicit():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert not result.evaluation_evidence
    assert result.status == "potential_ssti"


def test_evaluation_evidence_is_not_inferred_from_response_change():
    analysis = SSTIAnalyzer().analyze(
        "{{ 7 * 7 }}"
    )

    result = SSTIValidator().validate(
        response(content=b"before"),
        response(content=b"49"),
        analysis,
    )

    assert not result.evaluation_evidence
    assert result.potential_ssti
    assert result.status == "potential_ssti"


def test_response_change_without_indicator_is_not_potential_ssti():
    result = SSTIValidator().validate(
        response(content=b"before"),
        response(content=b"after"),
        SSTIAnalysis(),
    )

    assert result.response_changed
    assert not result.potential_ssti
    assert result.status == "no_indicator"


def test_status_change_without_indicator_is_not_potential_ssti():
    result = SSTIValidator().validate(
        response(status_code=200),
        response(status_code=500),
        SSTIAnalysis(),
    )

    assert result.status_changed
    assert not result.potential_ssti


def test_candidate_status_is_preserved():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(status_code=200),
        response(status_code=201),
        analysis,
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 201


def test_evidence_is_populated():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.evidence
    assert all(result.evidence)


def test_invalid_baseline_type_is_rejected():
    with pytest.raises(TypeError):
        SSTIValidator().validate(
            {},
            response(),
            SSTIAnalysis(),
        )


def test_invalid_candidate_type_is_rejected():
    with pytest.raises(TypeError):
        SSTIValidator().validate(
            response(),
            {},
            SSTIAnalysis(),
        )


def test_invalid_analysis_type_is_rejected():
    with pytest.raises(TypeError):
        SSTIValidator().validate(
            response(),
            response(),
            {},
        )


def test_multiple_response_changes_are_recorded():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(
            status_code=200,
            content=b"before",
        ),
        response(
            status_code=500,
            content=b"after",
        ),
        analysis,
    )

    assert result.status_changed
    assert result.content_changed
    assert result.content_length_changed
    assert result.response_changed


def test_potential_ssti_requires_indicator_and_response_change():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(content=b"one"),
        response(content=b"two"),
        analysis,
    )

    assert analysis.detected
    assert result.response_changed
    assert result.potential_ssti


def test_indicator_detected_without_response_change():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(content=b"same"),
        response(content=b"same"),
        analysis,
    )

    assert result.status == "indicator_detected"
    assert not result.potential_ssti


def test_status_values_are_valid():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(),
        response(content=b"changed"),
        analysis,
    )

    assert result.status in {
        "no_indicator",
        "indicator_detected",
        "potential_ssti",
        "evaluation_evidence",
    }


def test_evaluation_evidence_status_does_not_require_response_change():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(),
        response(),
        analysis,
        evaluation_evidence=True,
    )

    assert result.status == "evaluation_evidence"
    assert not result.response_changed


def test_empty_body_comparison():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(content=b""),
        response(content=b"changed"),
        analysis,
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_ssti


def test_header_changes_are_not_used_as_confirmation():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    baseline = HttpResponse(
        status_code=200,
        url="https://example.com/render",
        headers={"X-Test": "one"},
        content=b"same",
        cookies={},
        response_time=0.1,
        content_length=4,
    )

    candidate = HttpResponse(
        status_code=200,
        url="https://example.com/render",
        headers={"X-Test": "two"},
        content=b"same",
        cookies={},
        response_time=0.1,
        content_length=4,
    )

    result = SSTIValidator().validate(
        baseline,
        candidate,
        analysis,
    )

    assert not result.response_changed
    assert not result.potential_ssti


def test_evaluation_evidence_is_visible_in_evidence():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(),
        response(),
        analysis,
        evaluation_evidence=True,
    )

    assert any(
        "Evaluation evidence: True" in item
        for item in result.evidence
    )


def test_potential_ssti_does_not_mean_confirmed_execution():
    analysis = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    result = SSTIValidator().validate(
        response(content=b"before"),
        response(content=b"after"),
        analysis,
    )

    assert result.potential_ssti
    assert not result.evaluation_evidence
    assert result.status == "potential_ssti"
