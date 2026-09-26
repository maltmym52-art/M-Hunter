import pytest

from m_hunter.analyzers.host_header_injection import (
    HostHeaderInjectionAnalyzer,
)
from m_hunter.core.response import HttpResponse
from m_hunter.validation.host_header_injection import (
    HostHeaderInjectionValidator,
)


def make_response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
    repeated_headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.test",
        headers=headers or {},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
        repeated_headers=repeated_headers or {},
    )


@pytest.fixture
def validator():
    return HostHeaderInjectionValidator()


@pytest.fixture
def analyzer():
    return HostHeaderInjectionAnalyzer()


def test_no_indicator(validator, analyzer):
    baseline = make_response()
    candidate = make_response()
    analysis = analyzer.analyze()

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.status == "no_indicator"
    assert result.potential_host_header_injection is False


def test_indicator_without_change(validator, analyzer):
    baseline = make_response()
    candidate = make_response()
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.status == "indicator_detected"
    assert result.potential_host_header_injection is False


def test_status_change(validator, analyzer):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=302)
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_host_header_injection is True
    assert result.status == "potential_host_header_injection"


def test_content_change(validator, analyzer):
    baseline = make_response(content=b"before")
    candidate = make_response(content=b"after-content")
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.content_changed is True
    assert result.response_changed is True
    assert result.potential_host_header_injection is True


def test_content_length_change(validator, analyzer):
    baseline = make_response(content=b"one")
    candidate = make_response(content=b"changed-content")
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.content_length_changed is True
    assert result.response_changed is True


def test_header_change(validator, analyzer):
    baseline = make_response(
        headers={"Content-Type": "text/plain"},
    )
    candidate = make_response(
        headers={"Content-Type": "text/html"},
    )
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.potential_host_header_injection is True


def test_repeated_header_change(validator, analyzer):
    baseline = make_response(
        repeated_headers={"Set-Cookie": ["a=1"]},
    )
    candidate = make_response(
        repeated_headers={"Set-Cookie": ["a=1", "b=2"]},
    )
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.headers_changed is True


def test_behavior_change_without_response_change(
    validator,
    analyzer,
):
    baseline = make_response()
    candidate = make_response()
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
        behavior_changed=True,
    )

    assert result.behavior_changed is True
    assert result.potential_host_header_injection is True
    assert result.status == "potential_host_header_injection"


def test_behavior_change_without_indicator(
    validator,
    analyzer,
):
    baseline = make_response()
    candidate = make_response()
    analysis = analyzer.analyze()

    result = validator.compare(
        baseline,
        candidate,
        analysis,
        behavior_changed=True,
    )

    assert result.behavior_changed is True
    assert result.potential_host_header_injection is False
    assert result.status == "behavior_changed"


def test_response_change_without_indicator(
    validator,
    analyzer,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=302)
    analysis = analyzer.analyze()

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.response_changed is True
    assert result.potential_host_header_injection is False
    assert result.status == "response_changed"


def test_all_response_flags(validator, analyzer):
    baseline = make_response(
        status_code=200,
        content=b"before",
        headers={"X-Test": "one"},
    )
    candidate = make_response(
        status_code=302,
        content=b"after-content",
        headers={"X-Test": "two"},
    )
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
        behavior_changed=True,
    )

    assert result.status_changed
    assert result.content_changed
    assert result.content_length_changed
    assert result.headers_changed
    assert result.response_changed
    assert result.behavior_changed
    assert result.potential_host_header_injection


def test_evidence_contains_statuses(validator, analyzer):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=302)
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert "Baseline status: 200" in result.evidence
    assert "Candidate status: 302" in result.evidence


def test_evidence_contains_indicator_types(
    validator,
    analyzer,
):
    baseline = make_response()
    candidate = make_response(
        headers={"X-Test": "changed"},
    )
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert "host_header" in result.evidence


def test_invalid_baseline(validator, analyzer):
    with pytest.raises(TypeError):
        validator.compare(
            "invalid",
            make_response(),
            analyzer.analyze(),
        )


def test_invalid_candidate(validator, analyzer):
    with pytest.raises(TypeError):
        validator.compare(
            make_response(),
            "invalid",
            analyzer.analyze(),
        )


def test_invalid_analysis(validator):
    with pytest.raises(TypeError):
        validator.compare(
            make_response(),
            make_response(),
            "invalid",
        )


def test_invalid_behavior_flag(validator, analyzer):
    with pytest.raises(TypeError):
        validator.compare(
            make_response(),
            make_response(),
            analyzer.analyze(),
            behavior_changed="yes",
        )


def test_same_response_flags_are_false(
    validator,
    analyzer,
):
    response = make_response()
    analysis = analyzer.analyze()

    result = validator.compare(
        response,
        response,
        analysis,
    )

    assert result.status_changed is False
    assert result.content_changed is False
    assert result.content_length_changed is False
    assert result.headers_changed is False
    assert result.response_changed is False


def test_result_fields_are_populated(
    validator,
    analyzer,
):
    result = validator.compare(
        make_response(),
        make_response(),
        analyzer.analyze(),
    )

    assert result.baseline_status == 200
    assert result.candidate_status == 200
    assert isinstance(result.evidence, str)
    assert result.evidence


def test_indicator_with_header_change(
    validator,
    analyzer,
):
    baseline = make_response(
        headers={"Location": "https://example.test/a"},
    )
    candidate = make_response(
        headers={"Location": "https://example.test/b"},
    )
    analysis = analyzer.analyze(
        response_headers={
            "Location": "https://example.test/a",
        },
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.headers_changed
    assert result.potential_host_header_injection
    assert result.status == "potential_host_header_injection"


def test_indicator_with_status_and_behavior_change(
    validator,
    analyzer,
):
    baseline = make_response(status_code=200)
    candidate = make_response(status_code=302)
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
        behavior_changed=True,
    )

    assert result.potential_host_header_injection
    assert result.status == "potential_host_header_injection"


def test_candidate_content_length_is_derived(
    validator,
    analyzer,
):
    baseline = make_response(content=b"abc")
    candidate = make_response(content=b"abcdef")
    analysis = analyzer.analyze()

    result = validator.compare(
        baseline,
        candidate,
        analysis,
    )

    assert result.content_length_changed is True
    assert result.response_changed is True


def test_external_host_indicator_with_behavior_change(
    validator,
    analyzer,
):
    baseline = make_response()
    candidate = make_response()
    analysis = analyzer.analyze(
        headers={"Host": "attacker.test"},
        expected_host="example.test",
    )

    result = validator.compare(
        baseline,
        candidate,
        analysis,
        behavior_changed=True,
    )

    assert result.potential_host_header_injection is True
    assert "external_host" in result.evidence
