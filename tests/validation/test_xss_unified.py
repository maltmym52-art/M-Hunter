from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.analyzers.xss import XSSAnalysis, XSSContext, XSSReflection
from m_hunter.validation.analysis import AnalysisDisposition
from m_hunter.validation.xss_unified import XSSUnifiedValidator


def make_analysis(context=XSSContext.HTML_TEXT):
    return AnalysisResult(
        analyzer_name="xss",
        data=XSSAnalysis(
            marker="M-HUNTER",
            reflected=True,
            reflections=[
                XSSReflection(
                    value="M-HUNTER",
                    context=context,
                    position=6,
                )
            ],
        ),
    )


def make_context():
    return AnalysisContext(
        request_url="https://example.com/search?q=M-HUNTER",
        options={"parameter": "q"},
    )


class TestXSSUnifiedValidator:
    def test_reflection_creates_finding_decision(self):
        result = XSSUnifiedValidator().validate(
            make_analysis(),
            make_context(),
        )

        assert result.disposition == AnalysisDisposition.FINDING
        assert result.candidate is not None
        assert result.candidate.severity == "Medium"
        assert result.candidate.cwe == "CWE-79"

    def test_javascript_context_is_high(self):
        result = XSSUnifiedValidator().validate(
            make_analysis(XSSContext.JAVASCRIPT),
            make_context(),
        )

        assert result.disposition == AnalysisDisposition.FINDING
        assert result.candidate.severity == "High"
        assert result.metadata["status"] == "potential_xss"

    def test_json_reflection_is_low(self):
        result = XSSUnifiedValidator().validate(
            make_analysis(XSSContext.JSON),
            make_context(),
        )

        assert result.disposition == AnalysisDisposition.FINDING
        assert result.candidate.severity == "Low"
        assert result.metadata["status"] == "reflection_only"

    def test_no_reflection_is_informational(self):
        analysis = AnalysisResult(
            analyzer_name="xss",
            data=XSSAnalysis(
                marker="M-HUNTER",
                reflected=False,
                reflections=[],
            ),
        )

        result = XSSUnifiedValidator().validate(
            analysis,
            make_context(),
        )

        assert result.disposition == AnalysisDisposition.INFORMATIONAL

    def test_execution_is_not_claimed(self):
        result = XSSUnifiedValidator().validate(
            make_analysis(XSSContext.JAVASCRIPT),
            make_context(),
        )

        assert result.candidate.metadata["execution_confirmed"] is False
