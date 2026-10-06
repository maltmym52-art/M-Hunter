from m_hunter.analyzers.coep import (
    COEPAnalysis,
    COEPAnalyzer,
    COEPIndicatorType,
)
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.validation.analysis import AnalysisDisposition
from m_hunter.validation.coep_unified import COEPUnifiedValidator


def make_context() -> AnalysisContext:
    return AnalysisContext(
        request_url="https://example.com",
        target="example.com",
    )


def make_result(analysis: COEPAnalysis) -> AnalysisResult:
    return AnalysisResult(
        analyzer_name="coep",
        data=analysis,
    )


def test_coep_unified_validator_creates_findings_for_indicators():
    analysis = COEPAnalysis(
        detected=True,
        indicators=(
            (
                __import__(
                    "m_hunter.analyzers.coep",
                    fromlist=["COEPIndicator"],
                ).COEPIndicator(
                    COEPIndicatorType.POLICY_MISSING,
                    "Cross-Origin-Embedder-Policy",
                )
            ),
        ),
    )

    validator = COEPUnifiedValidator()

    decisions = validator.validate_many(
        make_result(analysis),
        make_context(),
    )

    assert len(decisions) == 1
    assert decisions[0].disposition == AnalysisDisposition.FINDING
    assert decisions[0].candidate is not None
    assert decisions[0].candidate.cwe == "CWE-693"
    assert decisions[0].candidate.owasp == "A05:2021"
    assert decisions[0].candidate.target == "example.com"


def test_coep_unified_validator_preserves_multiple_indicators():
    from m_hunter.analyzers.coep import COEPIndicator

    analysis = COEPAnalysis(
        detected=True,
        indicators=(
            COEPIndicator(
                COEPIndicatorType.POLICY_PRESENT,
                "Cross-Origin-Embedder-Policy",
                "unsafe-none",
            ),
            COEPIndicator(
                COEPIndicatorType.UNSAFE_NONE,
                "unsafe-none",
                "unsafe-none",
            ),
            COEPIndicator(
                COEPIndicatorType.MULTIPLE_POLICIES,
                "Cross-Origin-Embedder-Policy",
                "unsafe-none, unsafe-none",
            ),
        ),
    )

    validator = COEPUnifiedValidator()

    decisions = validator.validate_many(
        make_result(analysis),
        make_context(),
    )

    assert len(decisions) == len(analysis.indicators)
    assert all(
        decision.disposition == AnalysisDisposition.FINDING
        for decision in decisions
    )


def test_coep_unified_validator_rejects_invalid_analysis():
    validator = COEPUnifiedValidator()

    result = AnalysisResult(
        analyzer_name="coep",
        data=None,
    )

    try:
        validator.validate(
            result,
            make_context(),
        )
    except TypeError as exc:
        assert "COEPAnalysis" in str(exc)
    else:
        raise AssertionError("Expected TypeError")
