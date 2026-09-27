from m_hunter.analyzers.coep import (
    COEPAnalysis,
    COEPIndicator,
    COEPIndicatorType,
)
from m_hunter.analyzers.coep_finding import COEPFindingAnalyzer
from m_hunter.core.finding import Finding


def analysis(*indicators):
    return COEPAnalysis(
        detected=True,
        indicators=tuple(indicators),
    )


def indicator(kind, name="require-corp", value=None):
    return COEPIndicator(
        type=kind,
        name=name,
        value=value,
    )


def test_name():
    assert COEPFindingAnalyzer.name == "coep_finding"


def test_creates_finding():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(
                COEPIndicatorType.UNSAFE_NONE,
                value="unsafe-none",
            )
        ),
        target="https://example.com",
    )

    assert len(result) == 1
    assert isinstance(result[0], Finding)


def test_target_preserved():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.POLICY_MISSING)
        ),
        target="https://example.com",
    )

    assert result[0].target == "https://example.com"


def test_endpoint_preserved():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.POLICY_MISSING)
        ),
        target="https://example.com",
        endpoint="/account",
    )

    assert result[0].endpoint == "/account"


def test_unsafe_none_is_medium():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.UNSAFE_NONE)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Medium"


def test_missing_policy_is_low():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.POLICY_MISSING)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Low"


def test_require_corp_is_info():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.REQUIRE_CORP)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Info"


def test_credentialless_is_low():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.CREDENTIALLESS)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Low"


def test_invalid_policy_is_medium():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.INVALID_POLICY)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Medium"


def test_multiple_policies_is_low():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.MULTIPLE_POLICIES)
        ),
        target="https://example.com",
    )

    assert result[0].severity == "Low"


def test_evidence_contains_value():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(
                COEPIndicatorType.UNSAFE_NONE,
                value="unsafe-none",
            )
        ),
        target="https://example.com",
    )

    assert "unsafe-none" in result[0].evidence


def test_missing_policy_evidence():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(
                COEPIndicatorType.POLICY_MISSING,
                name="Cross-Origin-Embedder-Policy",
            )
        ),
        target="https://example.com",
    )

    assert "Cross-Origin-Embedder-Policy" in result[0].evidence


def test_cwe_present():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.UNSAFE_NONE)
        ),
        target="https://example.com",
    )

    assert result[0].cwe == "CWE-693"


def test_owasp_present():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.UNSAFE_NONE)
        ),
        target="https://example.com",
    )

    assert result[0].owasp == "A05:2021"


def test_description_is_conservative():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.REQUIRE_CORP)
        ),
        target="https://example.com",
    )

    assert "does not by itself prove" in result[0].description


def test_remediation_present():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.REQUIRE_CORP)
        ),
        target="https://example.com",
    )

    assert result[0].remediation


def test_all_indicators():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            *(
                indicator(kind, name=kind.value)
                for kind in COEPIndicatorType
            )
        ),
        target="https://example.com",
    )

    assert len(result) == len(COEPIndicatorType)


def test_multiple_findings_preserve_order():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.POLICY_MISSING),
            indicator(
                COEPIndicatorType.UNSAFE_NONE,
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
        COEPFindingAnalyzer().analyze(
            object(),
            target="https://example.com",
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_invalid_target():
    try:
        COEPFindingAnalyzer().analyze(
            analysis(
                indicator(COEPIndicatorType.REQUIRE_CORP)
            ),
            target="",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")


def test_invalid_endpoint():
    try:
        COEPFindingAnalyzer().analyze(
            analysis(
                indicator(COEPIndicatorType.REQUIRE_CORP)
            ),
            target="https://example.com",
            endpoint=123,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_finding_status_defaults_open():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.UNSAFE_NONE)
        ),
        target="https://example.com",
    )

    assert result[0].status == "open"


def test_confidence_preserved():
    result = COEPFindingAnalyzer().analyze(
        analysis(
            indicator(COEPIndicatorType.UNSAFE_NONE)
        ),
        target="https://example.com",
    )

    assert result[0].confidence == "High"
