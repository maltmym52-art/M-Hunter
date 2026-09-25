import pytest

from m_hunter.analyzers.xss import XSSAnalysis, XSSContext, XSSReflection
from m_hunter.core.response import HttpResponse
from m_hunter.validation.xss import XSSValidator


def response(
    content: bytes,
    *,
    status_code: int = 200,
) -> HttpResponse:
    return HttpResponse(
        status_code=status_code,
        url="https://example.com/search",
        headers={"content-type": "text/html"},
        content=content,
        cookies={},
        response_time=0.1,
        content_length=len(content),
    )


def analysis(
    *,
    reflected: bool = True,
    context: XSSContext = XSSContext.HTML_TEXT,
) -> XSSAnalysis:
    reflections = (
        [
            XSSReflection(
                value="M-HUNTER",
                context=context,
                position=6,
            )
        ]
        if reflected
        else []
    )

    return XSSAnalysis(
        marker="M-HUNTER",
        reflected=reflected,
        reflections=reflections,
    )


class TestXSSValidator:
    def test_validator_creation(self):
        assert XSSValidator() is not None

    def test_invalid_baseline(self):
        validator = XSSValidator()

        with pytest.raises(TypeError):
            validator.validate(
                "invalid",
                response(b"ok"),
                analysis(),
            )

    def test_invalid_candidate(self):
        validator = XSSValidator()

        with pytest.raises(TypeError):
            validator.validate(
                response(b"ok"),
                "invalid",
                analysis(),
            )

    def test_invalid_analysis(self):
        validator = XSSValidator()

        with pytest.raises(TypeError):
            validator.validate(
                response(b"ok"),
                response(b"ok"),
                "invalid",
            )

    def test_no_reflection(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"<html>safe</html>"),
            response(b"<html>safe</html>"),
            analysis(reflected=False),
        )

        assert result.status == "no_reflection"
        assert result.reflection_only is False
        assert result.potential_xss is False
        assert result.confirmed_execution is False

    def test_reflection_only(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"<html>safe</html>"),
            response(b"<html>M-HUNTER</html>"),
            analysis(),
        )

        assert result.status == "potential_xss"
        assert result.potential_xss is True
        assert result.confirmed_execution is False

    def test_html_reflection_does_not_confirm_execution(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"<html>safe</html>"),
            response(b"<html>M-HUNTER</html>"),
            analysis(context=XSSContext.HTML_TEXT),
        )

        assert result.confirmed_execution is False
        assert result.execution_evidence is False

    def test_javascript_context_is_potential_xss(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"<script>safe</script>"),
            response(b"<script>M-HUNTER</script>"),
            analysis(context=XSSContext.JAVASCRIPT),
        )

        assert result.potential_xss is True
        assert result.status == "potential_xss"

    def test_json_reflection_is_not_potential_executable_context(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b'{"value":"safe"}'),
            response(b'{"value":"M-HUNTER"}'),
            analysis(context=XSSContext.JSON),
        )

        assert result.potential_xss is False
        assert result.confirmed_execution is False

    def test_response_change_is_recorded(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"<html>safe</html>"),
            response(b"<html>M-HUNTER</html>"),
            analysis(),
        )

        assert result.response_changed is True
        assert "response content changed" in result.evidence

    def test_status_change_is_recorded(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"safe", status_code=200),
            response(b"M-HUNTER", status_code=500),
            analysis(),
        )

        assert result.response_changed is True
        assert any(
            "status code changed" in item
            for item in result.evidence
        )

    def test_execution_evidence_can_be_explicitly_supplied(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"<html>safe</html>"),
            response(b"<html>M-HUNTER</html>"),
            analysis(),
            execution_evidence=True,
        )

        assert result.execution_evidence is True
        assert result.confirmed_execution is True
        assert result.status == "execution_evidence"

    def test_execution_evidence_is_not_inferred_from_reflection(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"<html>safe</html>"),
            response(b"<html>M-HUNTER</html>"),
            analysis(context=XSSContext.JAVASCRIPT),
        )

        assert result.confirmed_execution is False
        assert result.status == "potential_xss"

    def test_execution_evidence_is_recorded(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
            execution_evidence=True,
        )

        assert any(
            "explicit execution evidence" in item
            for item in result.evidence
        )

    def test_reflection_count_is_recorded(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
        )

        assert any(
            "marker reflected 1 time" in item
            for item in result.evidence
        )

    def test_context_is_recorded(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"safe"),
            response(b"<script>M-HUNTER</script>"),
            analysis(context=XSSContext.JAVASCRIPT),
        )

        assert any(
            "javascript" in item
            for item in result.evidence
        )

    def test_baseline_and_candidate_are_preserved(self):
        validator = XSSValidator()

        baseline = response(b"safe")
        candidate = response(b"M-HUNTER")

        result = validator.validate(
            baseline,
            candidate,
            analysis(),
        )

        assert result.baseline is baseline
        assert result.candidate is candidate

    def test_analysis_is_preserved(self):
        validator = XSSValidator()
        current_analysis = analysis()

        result = validator.validate(
            response(b"safe"),
            response(b"M-HUNTER"),
            current_analysis,
        )

        assert result.analysis is current_analysis

    def test_evidence_is_immutable_tuple(self):
        validator = XSSValidator()

        result = validator.validate(
            response(b"safe"),
            response(b"M-HUNTER"),
            analysis(),
        )

        assert isinstance(result.evidence, tuple)
