import pytest

from m_hunter.analyzers.hpp import HPPAnalyzer
from m_hunter.core.response import HttpResponse
from m_hunter.validation.hpp import (
    HPPValidationResult,
    HPPValidator,
)


def make_response(
    *,
    status_code=200,
    content=b"same",
    headers=None,
):
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/api/test",
        headers=headers or {"content-type": "application/json"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


@pytest.fixture
def analyzer():
    return HPPAnalyzer()


@pytest.fixture
def validator():
    return HPPValidator()


def test_no_indicator(validator, analyzer):
    result = validator.compare(
        make_response(),
        make_response(),
        analyzer.analyze(),
    )

    assert isinstance(result, HPPValidationResult)
    assert result.status == "no_indicator"
    assert not result.potential_hpp_issue
    assert result.evidence == []


def test_indicator_without_response_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    result = validator.compare(
        make_response(),
        make_response(),
        analysis,
    )

    assert result.status == "indicator_detected"
    assert not result.potential_hpp_issue


def test_status_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    result = validator.compare(
        make_response(status_code=200),
        make_response(status_code=400),
        analysis,
    )

    assert result.status_changed
    assert result.response_changed
    assert result.potential_hpp_issue
    assert result.status == "potential_hpp_issue"
    assert any(
        "Status changed" in item
        for item in result.evidence
    )


def test_content_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        body="id=1&id=2"
    )

    result = validator.compare(
        make_response(content=b"before"),
        make_response(content=b"after"),
        analysis,
    )

    assert result.content_changed
    assert result.response_changed
    assert result.potential_hpp_issue


def test_content_length_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        params={"id": ["1", "2"]}
    )

    result = validator.compare(
        make_response(content=b"one"),
        make_response(content=b"three"),
        analysis,
    )

    assert result.content_length_changed
    assert result.response_changed
    assert result.potential_hpp_issue


def test_header_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?role=user&role=admin"
    )

    result = validator.compare(
        make_response(
            headers={"content-type": "application/json"}
        ),
        make_response(
            headers={
                "content-type": "application/json",
                "x-test": "changed",
            }
        ),
        analysis,
    )

    assert result.headers_changed
    assert result.response_changed
    assert result.potential_hpp_issue


def test_behavior_change(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    result = validator.compare(
        make_response(),
        make_response(),
        analysis,
        behavior_changed=True,
    )

    assert result.behavior_changed
    assert result.potential_hpp_issue
    assert result.status == "potential_hpp_issue"
    assert "Application behavior changed." in result.evidence


def test_response_changed_without_indicator(
    validator,
    analyzer,
):
    result = validator.compare(
        make_response(content=b"one"),
        make_response(content=b"two"),
        analyzer.analyze(),
    )

    assert result.response_changed
    assert not result.potential_hpp_issue
    assert result.status == "response_changed"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"baseline": object()},
        {"candidate": object()},
        {"analysis": object()},
    ],
)
def test_invalid_arguments_rejected(
    validator,
    analyzer,
    kwargs,
):
    values = {
        "baseline": make_response(),
        "candidate": make_response(),
        "analysis": analyzer.analyze(),
    }
    values.update(kwargs)

    with pytest.raises(TypeError):
        validator.compare(**values)


def test_invalid_behavior_flag(
    validator,
    analyzer,
):
    with pytest.raises(TypeError):
        validator.compare(
            make_response(),
            make_response(),
            analyzer.analyze(),
            behavior_changed="yes",
        )


@pytest.mark.parametrize(
    "analysis_input",
    [
        {"url": "https://example.com/?id=1&id=2"},
        {"body": "role=user&role=admin"},
        {"params": {"id": ["1", "2"]}},
        {"url": "https://example.com/?a=1&a=2"},
    ],
)
def test_detected_indicators_can_be_validated(
    validator,
    analyzer,
    analysis_input,
):
    analysis = analyzer.analyze(**analysis_input)

    result = validator.compare(
        make_response(content=b"before"),
        make_response(content=b"after"),
        analysis,
    )

    assert result.potential_hpp_issue
    assert result.status == "potential_hpp_issue"


def test_multiple_response_differences(
    validator,
    analyzer,
):
    analysis = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    result = validator.compare(
        make_response(
            status_code=200,
            content=b"before",
            headers={"content-type": "application/json"},
        ),
        make_response(
            status_code=500,
            content=b"after-response",
            headers={"content-type": "text/plain"},
        ),
        analysis,
    )

    assert result.status_changed
    assert result.content_changed
    assert result.content_length_changed
    assert result.headers_changed
    assert result.response_changed
    assert result.potential_hpp_issue
    assert len(result.evidence) == 4
