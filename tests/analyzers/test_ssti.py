import pytest

from m_hunter.analyzers.ssti import (
    SSTIAnalysis,
    SSTIAnalyzer,
    SSTIEngine,
    SSTIIndicatorType,
)


def test_jinja_expression_is_detected():
    result = SSTIAnalyzer().analyze(
        "Hello {{ username }}"
    )

    assert result.detected
    assert result.template_syntax_detected
    assert SSTIEngine.JINJA2 in result.engines


def test_freemarker_expression_is_detected():
    result = SSTIAnalyzer().analyze(
        "Hello ${username}"
    )

    assert result.detected
    assert SSTIEngine.FREEMARKER in result.engines


def test_velocity_directive_is_detected():
    result = SSTIAnalyzer().analyze(
        "#set($x = 1)"
    )

    assert result.detected
    assert SSTIEngine.VELOCITY in result.engines


def test_thymeleaf_marker_is_detected():
    result = SSTIAnalyzer().analyze(
        '<span th:text="${name}"></span>'
    )

    assert result.detected
    assert SSTIEngine.THYMELEAF in result.engines


def test_erb_expression_is_detected():
    result = SSTIAnalyzer().analyze(
        "<%= username %>"
    )

    assert result.detected
    assert SSTIEngine.ERB in result.engines


def test_django_template_syntax_is_detected():
    result = SSTIAnalyzer().analyze(
        "{{ user.name }}"
    )

    assert result.detected
    assert SSTIEngine.DJANGO in result.engines


def test_twig_template_syntax_is_detected():
    result = SSTIAnalyzer().analyze(
        "{{ user.name }}"
    )

    assert result.detected
    assert SSTIEngine.TWIG in result.engines


def test_reflection_marker_is_detected():
    result = SSTIAnalyzer().analyze(
        "Hello UNIQUE_MARKER",
        marker="UNIQUE_MARKER",
    )

    assert result.expression_reflected
    assert any(
        indicator.type
        == SSTIIndicatorType.EXPRESSION_REFLECTION
        for indicator in result.indicators
    )


def test_missing_reflection_marker_is_not_detected():
    result = SSTIAnalyzer().analyze(
        "Hello world",
        marker="UNIQUE_MARKER",
    )

    assert not result.expression_reflected


def test_engine_marker_is_detected():
    result = SSTIAnalyzer().analyze(
        "Rendered by Jinja2"
    )

    assert result.engine_marker_detected
    assert SSTIEngine.JINJA2 in result.engines


def test_engine_marker_is_case_insensitive():
    result = SSTIAnalyzer().analyze(
        "Rendered by JINJA2"
    )

    assert result.engine_marker_detected
    assert SSTIEngine.JINJA2 in result.engines


def test_multiple_indicators_are_collected():
    result = SSTIAnalyzer().analyze(
        "Jinja2 {{ username }} UNIQUE",
        marker="UNIQUE",
    )

    assert result.indicator_count >= 3
    assert len(result.indicators) == result.indicator_count


def test_indicator_evidence_is_preserved():
    result = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    assert result.indicators
    assert all(
        indicator.evidence
        for indicator in result.indicators
    )


def test_indicator_positions_are_recorded():
    content = "prefix {{ username }}"
    result = SSTIAnalyzer().analyze(content)

    syntax = next(
        indicator
        for indicator in result.indicators
        if indicator.type == SSTIIndicatorType.TEMPLATE_SYNTAX
    )

    assert syntax.position == content.index("{{")


def test_analysis_names_match_types():
    result = SSTIAnalyzer().analyze(
        "{{ username }}"
    )

    assert set(result.names) == {
        indicator_type.value
        for indicator_type in result.types
    }


def test_empty_content_is_clean():
    result = SSTIAnalyzer().analyze("")

    assert isinstance(result, SSTIAnalysis)
    assert not result.detected
    assert result.indicator_count == 0
    assert result.engines == []
    assert result.types == []


def test_plain_text_is_clean():
    result = SSTIAnalyzer().analyze(
        "This is ordinary response content."
    )

    assert not result.detected


def test_bytes_content_is_supported():
    result = SSTIAnalyzer().analyze(
        b"Hello {{ username }}"
    )

    assert result.detected


def test_invalid_content_type_is_rejected():
    with pytest.raises(TypeError):
        SSTIAnalyzer().analyze(123)


def test_invalid_marker_type_is_rejected():
    with pytest.raises(TypeError):
        SSTIAnalyzer().analyze(
            "response",
            marker=123,
        )


def test_empty_marker_does_not_create_reflection():
    result = SSTIAnalyzer().analyze(
        "response",
        marker="",
    )

    assert not result.expression_reflected


def test_template_detection_does_not_claim_execution():
    result = SSTIAnalyzer().analyze(
        "{{ 7 * 7 }}"
    )

    assert result.detected
    assert result.template_syntax_detected
    assert not hasattr(result, "confirmed_execution")


def test_engine_list_contains_unique_values():
    result = SSTIAnalyzer().analyze(
        "{{ one }} {{ two }}"
    )

    assert len(result.engines) == len(set(result.engines))


def test_indicator_types_are_unique():
    result = SSTIAnalyzer().analyze(
        "{{ one }} UNIQUE",
        marker="UNIQUE",
    )

    assert len(result.types) == len(set(result.types))


def test_analysis_names_are_unique():
    result = SSTIAnalyzer().analyze(
        "{{ one }} UNIQUE",
        marker="UNIQUE",
    )

    assert len(result.names) == len(set(result.names))


def test_jinja_marker_is_not_execution_proof():
    result = SSTIAnalyzer().analyze(
        "jinja2"
    )

    assert result.engine_marker_detected
    assert result.detected


def test_multiple_engine_syntaxes_are_detected():
    result = SSTIAnalyzer().analyze(
        "{{ user }} ${user} #set($x = 1) <%= user %>"
    )

    assert result.detected
    assert len(result.engines) >= 3
