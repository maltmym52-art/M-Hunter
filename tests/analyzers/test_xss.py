import pytest

from m_hunter.analyzers.xss import (
    XSSAnalysis,
    XSSAnalyzer,
    XSSContext,
)
from m_hunter.core.response import HttpResponse


def make_response(
    content: bytes,
    *,
    content_type: str = "text/html",
) -> HttpResponse:
    return HttpResponse(
        status_code=200,
        url="https://example.com",
        headers={
            "Content-Type": content_type,
        },
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def test_analyzer_can_be_created():
    analyzer = XSSAnalyzer()

    assert isinstance(
        analyzer,
        XSSAnalyzer,
    )


def test_invalid_response_is_rejected():
    analyzer = XSSAnalyzer()

    with pytest.raises(TypeError):
        analyzer.analyze(
            "invalid",
            "MARKER",
        )


def test_invalid_marker_type_is_rejected():
    analyzer = XSSAnalyzer()

    with pytest.raises(TypeError):
        analyzer.analyze(
            make_response(b"MARKER"),
            123,
        )


def test_empty_marker_is_rejected():
    analyzer = XSSAnalyzer()

    with pytest.raises(ValueError):
        analyzer.analyze(
            make_response(b""),
            "",
        )


def test_no_reflection():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(b"<html>Hello</html>"),
        "M-HUNTER",
    )

    assert isinstance(result, XSSAnalysis)
    assert result.reflected is False
    assert result.reflection_count == 0
    assert result.contexts == ()


def test_html_text_reflection():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b"<html>Hello M-HUNTER</html>"
        ),
        "M-HUNTER",
    )

    assert result.reflected is True
    assert result.reflection_count == 1
    assert result.contexts == (
        XSSContext.HTML_TEXT,
    )
    assert result.executable_context is True


def test_html_attribute_reflection():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b'<input value="M-HUNTER">'
        ),
        "M-HUNTER",
    )

    assert result.reflected is True
    assert result.reflections[0].context == (
        XSSContext.HTML_ATTRIBUTE
    )


def test_url_attribute_reflection():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b'<a href="https://example.com/M-HUNTER">'
        ),
        "M-HUNTER",
    )

    assert result.reflected is True
    assert result.reflections[0].context == (
        XSSContext.URL
    )


def test_javascript_reflection():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b'<script>var value = "M-HUNTER";</script>'
        ),
        "M-HUNTER",
    )

    assert result.reflected is True
    assert result.reflections[0].context == (
        XSSContext.JAVASCRIPT
    )


def test_css_reflection():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b'<style>.item{content:"M-HUNTER"}</style>'
        ),
        "M-HUNTER",
    )

    assert result.reflected is True
    assert result.reflections[0].context == (
        XSSContext.CSS
    )


def test_multiple_reflections_are_detected():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b"<p>M-HUNTER</p><p>M-HUNTER</p>"
        ),
        "M-HUNTER",
    )

    assert result.reflection_count == 2


def test_contexts_are_unique():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b'<p>M-HUNTER</p><input value="M-HUNTER">'
        ),
        "M-HUNTER",
    )

    assert result.contexts == (
        XSSContext.HTML_TEXT,
        XSSContext.HTML_ATTRIBUTE,
    )


def test_reflection_positions_are_preserved():
    analyzer = XSSAnalyzer()

    content = b"AAAA-M-HUNTER-BBBB"
    result = analyzer.analyze(
        make_response(content),
        "M-HUNTER",
    )

    assert result.reflections[0].position == 5


def test_html_encoded_reflection_is_detected():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b"<p>M-HUNTER&amp;</p>"
        ),
        "M-HUNTER&",
    )

    assert result.reflected is True
    assert any(
        reflection.encoded
        for reflection in result.reflections
    )


def test_encoded_reflection_is_marked():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b'<input value="M-HUNTER&quot;">'
        ),
        'M-HUNTER"',
    )

    assert result.reflected is True
    assert result.reflections[0].encoded is True


def test_reflection_order_is_by_position():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b'<p>M-HUNTER</p>M-HUNTER'
        ),
        "M-HUNTER",
    )

    positions = [
        reflection.position
        for reflection in result.reflections
    ]

    assert positions == sorted(positions)


def test_json_response_can_be_analyzed():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b'{"value":"M-HUNTER"}',
            content_type="application/json",
        ),
        "M-HUNTER",
    )

    assert result.reflected is True


def test_reflection_does_not_mean_confirmed_xss():
    analyzer = XSSAnalyzer()

    result = analyzer.analyze(
        make_response(
            b"<p>M-HUNTER</p>"
        ),
        "M-HUNTER",
    )

    assert result.reflected is True
    assert result.executable_context is True
    assert not hasattr(
        result,
        "confirmed",
    )


def test_marker_with_regex_characters_is_safe():
    analyzer = XSSAnalyzer()

    marker = "M[HUNTER]+.*"

    result = analyzer.analyze(
        make_response(
            f"<p>{marker}</p>".encode()
        ),
        marker,
    )

    assert result.reflected is True
    assert result.reflection_count == 1
