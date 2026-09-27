from m_hunter.analyzers.permissions_policy import (
    PermissionsPolicyAnalysis,
    PermissionsPolicyIndicator,
    PermissionsPolicyIndicatorType,
)
from m_hunter.analyzers.permissions_policy_finding import (
    PermissionsPolicyFindingAnalyzer,
)
from m_hunter.core.finding import Finding


def analysis(*indicators):
    return PermissionsPolicyAnalysis(
        detected=True,
        indicators=tuple(indicators),
    )


def indicator(kind, name="camera", value=None):
    return PermissionsPolicyIndicator(
        type=kind,
        name=name,
        value=value,
    )


def test_name():
    assert PermissionsPolicyFindingAnalyzer.name == "permissions_policy_finding"


def test_creates_findings():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(
            indicator(
                PermissionsPolicyIndicatorType.WILDCARD_SOURCE,
                value="*",
            )
        ),
        target="https://example.com",
    )
    assert len(result) == 1
    assert isinstance(result[0], Finding)


def test_target_preserved():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(indicator(PermissionsPolicyIndicatorType.POLICY_MISSING)),
        target="https://example.com",
    )
    assert result[0].target == "https://example.com"


def test_endpoint_preserved():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(indicator(PermissionsPolicyIndicatorType.POLICY_MISSING)),
        target="https://example.com",
        endpoint="/account",
    )
    assert result[0].endpoint == "/account"


def test_wildcard_is_high():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(indicator(PermissionsPolicyIndicatorType.WILDCARD_SOURCE)),
        target="https://example.com",
    )
    assert result[0].severity == "High"


def test_missing_policy_is_low():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(indicator(PermissionsPolicyIndicatorType.POLICY_MISSING)),
        target="https://example.com",
    )
    assert result[0].severity == "Low"


def test_invalid_directive_is_medium():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(
            indicator(
                PermissionsPolicyIndicatorType.INVALID_DIRECTIVE,
                name="unknown",
            )
        ),
        target="https://example.com",
    )
    assert result[0].severity == "Medium"


def test_policy_present_is_info():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(indicator(PermissionsPolicyIndicatorType.POLICY_PRESENT)),
        target="https://example.com",
    )
    assert result[0].severity == "Info"


def test_evidence_contains_value():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(
            indicator(
                PermissionsPolicyIndicatorType.WILDCARD_SOURCE,
                value="camera *",
            )
        ),
        target="https://example.com",
    )
    assert "camera *" in result[0].evidence


def test_evidence_without_value():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(indicator(PermissionsPolicyIndicatorType.POLICY_MISSING)),
        target="https://example.com",
    )
    assert "Permissions-Policy" in result[0].evidence


def test_cwe_present():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(indicator(PermissionsPolicyIndicatorType.WILDCARD_SOURCE)),
        target="https://example.com",
    )
    assert result[0].cwe == "CWE-942"


def test_owasp_present():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(indicator(PermissionsPolicyIndicatorType.WILDCARD_SOURCE)),
        target="https://example.com",
    )
    assert result[0].owasp == "A05:2021"


def test_description_is_conservative():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(indicator(PermissionsPolicyIndicatorType.CAMERA)),
        target="https://example.com",
    )
    assert "does not by itself prove" in result[0].description


def test_remediation_present():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(indicator(PermissionsPolicyIndicatorType.CAMERA)),
        target="https://example.com",
    )
    assert result[0].remediation


def test_all_feature_indicators():
    kinds = [
        PermissionsPolicyIndicatorType.CAMERA,
        PermissionsPolicyIndicatorType.MICROPHONE,
        PermissionsPolicyIndicatorType.GEOLOCATION,
        PermissionsPolicyIndicatorType.PAYMENT,
        PermissionsPolicyIndicatorType.USB,
        PermissionsPolicyIndicatorType.FULLSCREEN,
        PermissionsPolicyIndicatorType.DISPLAY_CAPTURE,
    ]

    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(*(indicator(kind, name=kind.value) for kind in kinds)),
        target="https://example.com",
    )

    assert len(result) == len(kinds)


def test_all_security_metadata():
    kinds = list(PermissionsPolicyIndicatorType)

    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(*(indicator(kind, name=kind.value) for kind in kinds)),
        target="https://example.com",
    )

    assert len(result) == len(kinds)


def test_invalid_analysis_type():
    try:
        PermissionsPolicyFindingAnalyzer().analyze(
            object(),
            target="https://example.com",
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_invalid_target():
    try:
        PermissionsPolicyFindingAnalyzer().analyze(
            analysis(indicator(PermissionsPolicyIndicatorType.CAMERA)),
            target="",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")


def test_invalid_endpoint():
    try:
        PermissionsPolicyFindingAnalyzer().analyze(
            analysis(indicator(PermissionsPolicyIndicatorType.CAMERA)),
            target="https://example.com",
            endpoint=123,
        )
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")


def test_multiple_findings_preserve_order():
    result = PermissionsPolicyFindingAnalyzer().analyze(
        analysis(
            indicator(PermissionsPolicyIndicatorType.POLICY_MISSING),
            indicator(
                PermissionsPolicyIndicatorType.WILDCARD_SOURCE,
                value="camera *",
            ),
        ),
        target="https://example.com",
    )

    assert len(result) == 2
    assert result[0].severity == "Low"
    assert result[1].severity == "High"
