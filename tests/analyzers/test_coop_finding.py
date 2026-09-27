from m_hunter.analyzers.coop import (
    COOPAnalysis,
    COOPIndicator,
    COOPIndicatorType,
)
from m_hunter.analyzers.coop_finding import COOPFindingAnalyzer
from m_hunter.core.finding import Finding


def analysis(*indicators):
    return COOPAnalysis(
        detected=True,
        indicators=tuple(indicators),
    )


def indicator(kind, name="same-origin", value=None):
    return COOPIndicator(
        type=kind,
        name=name,
        value=value,
    )


def test_name():
    assert COOPFindingAnalyzer.name == "coop_finding"


def test_creates_finding():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(
                COOPIndicatorType.UNSAFE_NONE,
                value="unsafe-none",
            )
        ),
        target="https://example.com",
    )

    assert len(result) == 1
    assert isinstance(result[0], Finding)


def test_target_preserved():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.POLICY_MISSING)
        ),
        target="https://example.com",
    )

    assert result[0].target == "https://example.com"


def test_endpoint_preserved():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.POLICY_MISSING)
        ),
        target="https://example.com",
        endpoint="/account",
    )

    assert result[0].endpoint == "/account"


def test_unsafe_none_is_medium():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.UNSAFE_NONE)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Medium"


def test_missing_policy_is_low():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.POLICY_MISSING)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Low"


def test_same_origin_is_info():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.SAME_ORIGIN)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Info"


def test_invalid_policy_is_medium():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.INVALID_POLICY)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Medium"


def test_multiple_policies_is_low():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.MULTIPLE_POLICIES)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Low"


def test_evidence_contains_value():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(
                COOPIndicatorType.UNSAFE_NONE,
                value="unsafe-none",
            )
        ),
        target="https://example.com",
    )

    assert "unsafe-none" in result[0].evidence


def test_missing_policy_evidence():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(
                COOPIndicatorType.POLICY_MISSING,
                name="Cross-Origin-Opener-Policy",
            )
        ),
        target="https://example.com",
    )

    assert "Cross-Origin-Opener-Policy" in result[0].evidence


def test_cwe_present():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.UNSAFE_NONE)
        ),
        target="https://example.com",
    )

    assert result[0].cwe == "CWE-693"


def test_owasp_present():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.UNSAFE_NONE)
        ),
        target="https://example.com",
    )

    assert result[0].owasp == "A05:2021"


def test_description_is_conservative():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.SAME_ORIGIN)
        ),
        target="https://example.com",
    )

    assert "does not by itself prove" in result[0].description


def test_remediation_present():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.SAME_ORIGIN)
        ),
        target="https://example.com",
    )

    assert result[0].remediation


def test_all_indicators():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            *(
                indicator(kind, name=kind.value)
                for kind in COOPIndicatorType
            )
        ),
        target="https://example.com",
    )

    assert len(result) == len(COOPIndicatorType)


def test_multiple_findings_preserve_order():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.POLICY_MISSING),
            indicator(
                COOPIndicatorType.UNSAFE_NONE,
                value="unsafe-none",
            ),
        ),
        target="https://example.com",
    )

    assert len(result) == 2
    assert result[0].severity == "Low"
    assert result[1].severity == "Medium"


def test_invalid_analysis_type():
    try:
        COOPFindingAnalyzer().analyze(
            object(),
            target="https://example.com",
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_invalid_target():
    try:
        COOPFindingAnalyzer().analyze(
            analysis(
                indicator(COOPIndicatorType.SAME_ORIGIN)
            ),
            target="",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")


def test_invalid_endpoint():
    try:
        COOPFindingAnalyzer().analyze(
            analysis(
                indicator(COOPIndicatorType.SAME_ORIGIN)
            ),
            target="https://example.com",
            endpoint=123,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_finding_status_defaults_open():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.UNSAFE_NONE)
        ),
        target="https://example.com",
    )

    assert result[0].status == "open"


def test_confidence_preserved():
    result = COOPFindingAnalyzer().analyze(
        analysis(
            indicator(COOPIndicatorType.UNSAFE_NONE)
        ),
        target="https://example.com",
    )

    assert result[0].confidence == "High"
