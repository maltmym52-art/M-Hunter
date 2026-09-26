import pytest

from m_hunter.analyzers.command_injection import CommandInjectionAnalyzer
from m_hunter.core.response import HttpResponse
from m_hunter.validation.command_injection import (
    CommandInjectionValidationResult,
    CommandInjectionValidator,
)


def make_response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/test",
        headers=headers or {"content-type": "text/plain"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def analyzer():
    return CommandInjectionAnalyzer()


@pytest.fixture
def validator():
    return CommandInjectionValidator()


def test_no_indicator(
    validator,
    analyzer,
):
    analysis = analyzer.analyze()

    result = validator.compare(
        make_response(),
        make_response(),
        analysis,
    )

    assert isinstance(result, CommandInjectionValidationResult)
    assert result.status == "no_indicator"
    assert result.response_changed is False
    assert result.potential_command_injection is False


def test_indicator_without_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"cmd": "value"}
    )

    result = validator.compare(
        make_response(),
        make_response(),
        analysis,
    )

    assert result.status == "indicator_detected"
    assert result.potential_command_injection is False


def test_status_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"cmd": "value"}
    )

    result = validator.compare(
        make_response(status_code=200),
        make_response(status_code=500),
        analysis,
    )

    assert result.status_changed is True
    assert result.response_changed is True
    assert result.potential_command_injection is True
    assert result.status == "potential_command_injection"


def test_content_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"cmd": "value"}
    )

    result = validator.compare(
        make_response(content=b"before"),
        make_response(content=b"after-changed"),
        analysis,
    )

    assert result.content_changed is True
    assert result.content_length_changed is True
    assert result.response_changed is True
    assert result.potential_command_injection is True


def test_headers_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"cmd": "value"}
    )

    result = validator.compare(
        make_response(
            headers={"content-type": "text/plain"}
        ),
        make_response(
            headers={
                "content-type": "text/plain",
                "x-test": "changed",
            }
        ),
        analysis,
    )

    assert result.headers_changed is True
    assert result.response_changed is True
    assert result.potential_command_injection is True


def test_behavior_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"cmd": "value"}
    )

    result = validator.compare(
        make_response(),
        make_response(),
        analysis,
        behavior_changed=True,
    )

    assert result.behavior_changed is True
    assert result.potential_command_injection is True
    assert result.status == "potential_command_injection"


def test_behavior_change_without_indicator(
    validator,
    analyzer,
):
    analysis = analyzer.analyze()

    result = validator.compare(
        make_response(),
        make_response(),
        analysis,
        behavior_changed=True,
    )

    assert result.behavior_changed is True
    assert result.potential_command_injection is False
    assert result.status == "behavior_changed"


def test_response_change_without_indicator(
    validator,
    analyzer,
):
    analysis = analyzer.analyze()

    result = validator.compare(
        make_response(content=b"before"),
        make_response(content=b"after-changed"),
        analysis,
    )

    assert result.response_changed is True
    assert result.potential_command_injection is False
    assert result.status == "response_changed"


@pytest.mark.parametrize(
    "params",
    [
        {"cmd": "value;test"},
        {"shell": "value|test"},
        {"exec": "$(test)"},
        {"command": "`test`"},
    ],
)
def test_command_indicators_can_be_validated(
    validator,
    analyzer,
    params,
):
    analysis = analyzer.analyze(params=params)

    result = validator.compare(
        make_response(),
        make_response(content=b"changed"),
        analysis,
    )

    assert analysis.detected
    assert result.response_changed
    assert result.potential_command_injection


def test_evidence_contains_statuses(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"cmd": "value"}
    )

    result = validator.compare(
        make_response(status_code=200),
        make_response(status_code=500),
        analysis,
    )

    assert "Baseline status: 200" in result.evidence
    assert "Candidate status: 500" in result.evidence


def test_evidence_contains_behavior(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"cmd": "value"}
    )

    result = validator.compare(
        make_response(),
        make_response(),
        analysis,
        behavior_changed=True,
    )

    assert "Behavior changed: True" in result.evidence


@pytest.mark.parametrize(
    "bad_baseline",
    [None, object(), "response"],
)
def test_invalid_baseline(
    validator,
    analyzer,
    bad_baseline,
):
    with pytest.raises(TypeError):
        validator.compare(
            bad_baseline,
            make_response(),
            analyzer.analyze(),
        )


@pytest.mark.parametrize(
    "bad_candidate",
    [None, object(), "response"],
)
def test_invalid_candidate(
    validator,
    analyzer,
    bad_candidate,
):
    with pytest.raises(TypeError):
        validator.compare(
            make_response(),
            bad_candidate,
            analyzer.analyze(),
        )


@pytest.mark.parametrize(
    "bad_analysis",
    [None, object(), "analysis"],
)
def test_invalid_analysis(
    validator,
    bad_analysis,
):
    with pytest.raises(TypeError):
        validator.compare(
            make_response(),
            make_response(),
            bad_analysis,
        )


@pytest.mark.parametrize(
    "bad_behavior",
    [None, "true", 1, [], {}],
)
def test_invalid_behavior_changed(
    validator,
    analyzer,
    bad_behavior,
):
    with pytest.raises(TypeError):
        validator.compare(
            make_response(),
            make_response(),
            analyzer.analyze(),
            behavior_changed=bad_behavior,
        )
