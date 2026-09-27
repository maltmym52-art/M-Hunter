import pytest

from m_hunter.analyzers.corp import (
    CORPAnalysis,
    CORPIndicator,
    CORPIndicatorType,
)
from m_hunter.analyzers.corp_finding import CORPFindingAnalyzer
from m_hunter.core.finding import Finding


def analysis(*types):
    return CORPAnalysis(
        detected=True,
        indicators=tuple(
            CORPIndicator(
                type=kind,
                name=kind.value,
                value=kind.value,
            )
            for kind in types
        ),
    )


def test_name():
    assert CORPFindingAnalyzer.name == "corp_finding"


def test_creates_finding():
    findings = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.POLICY_PRESENT),
        target="https://example.com",
    )

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)


def test_target_preserved():
    findings = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        target="https://target.example",
    )

    assert findings[0].target == "https://target.example"


def test_endpoint_preserved():
    findings = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        target="https://example.com",
        endpoint="/resource.js",
    )

    assert findings[0].endpoint == "/resource.js"


def test_policy_present_severity():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.POLICY_PRESENT),
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"
    assert finding.confidence == "High"


def test_missing_policy_severity():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.POLICY_MISSING),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "High"


def test_same_origin_severity():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        target="https://example.com",
    )[0]

    assert finding.severity == "Info"


def test_same_site_severity():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.SAME_SITE),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"


def test_cross_origin_severity():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"


def test_invalid_policy_severity():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.INVALID_POLICY),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "High"


def test_multiple_policy_severity():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.MULTIPLE_POLICIES),
        target="https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Medium"


def test_missing_policy_evidence():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.POLICY_MISSING),
        target="https://example.com",
    )[0]

    assert "header is missing" in finding.evidence


def test_value_evidence():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        target="https://example.com",
    )[0]

    assert "same_origin" in finding.evidence


def test_cwe_and_owasp():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.INVALID_POLICY),
        target="https://example.com",
    )[0]

    assert finding.cwe == "CWE-16"
    assert finding.owasp == "A05:2021"


def test_policy_finding_metadata():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        target="https://example.com",
    )[0]

    assert finding.cwe == "CWE-693"
    assert finding.owasp == "A05:2021"


def test_description_is_conservative():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.CROSS_ORIGIN),
        target="https://example.com",
    )[0]

    assert "cross-origin" in finding.description.lower()
    assert "vulnerable" not in finding.description.lower()


def test_remediation():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.POLICY_MISSING),
        target="https://example.com",
    )[0]

    assert "Cross-Origin-Resource-Policy" in finding.remediation


def test_all_indicators():
    findings = CORPFindingAnalyzer().analyze(
        analysis(
            CORPIndicatorType.POLICY_PRESENT,
            CORPIndicatorType.POLICY_MISSING,
            CORPIndicatorType.SAME_ORIGIN,
            CORPIndicatorType.SAME_SITE,
            CORPIndicatorType.CROSS_ORIGIN,
            CORPIndicatorType.INVALID_POLICY,
            CORPIndicatorType.MULTIPLE_POLICIES,
        ),
        target="https://example.com",
    )

    assert len(findings) == 7


def test_multiple_findings_order():
    findings = CORPFindingAnalyzer().analyze(
        analysis(
            CORPIndicatorType.SAME_ORIGIN,
            CORPIndicatorType.INVALID_POLICY,
            CORPIndicatorType.CROSS_ORIGIN,
        ),
        target="https://example.com",
    )

    assert findings[0].title == (
        "Cross-Origin-Resource-Policy uses same-origin"
    )
    assert findings[1].title == (
        "Cross-Origin-Resource-Policy contains an invalid policy"
    )
    assert findings[2].title == (
        "Cross-Origin-Resource-Policy uses cross-origin"
    )


def test_invalid_analysis():
    with pytest.raises(TypeError):
        CORPFindingAnalyzer().analyze(
            object(),
            target="https://example.com",
        )


def test_invalid_target():
    with pytest.raises(ValueError):
        CORPFindingAnalyzer().analyze(
            analysis(CORPIndicatorType.SAME_ORIGIN),
            target="",
        )


def test_invalid_endpoint():
    with pytest.raises(TypeError):
        CORPFindingAnalyzer().analyze(
            analysis(CORPIndicatorType.SAME_ORIGIN),
            target="https://example.com",
            endpoint=123,
        )


def test_status_defaults_to_open():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        target="https://example.com",
    )[0]

    assert finding.status == "open"


def test_confidence_preserved():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.MULTIPLE_POLICIES),
        target="https://example.com",
    )[0]

    assert finding.confidence == "Medium"


def test_finding_id_exists():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        target="https://example.com",
    )[0]

    assert finding.id


def test_description_for_missing_policy():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.POLICY_MISSING),
        target="https://example.com",
    )[0]

    assert "does not define" in finding.description


def test_description_for_same_origin():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.SAME_ORIGIN),
        target="https://example.com",
    )[0]

    assert "same-origin" in finding.description


def test_description_for_same_site():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.SAME_SITE),
        target="https://example.com",
    )[0]

    assert "same-site" in finding.description


def test_description_for_invalid_policy():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.INVALID_POLICY),
        target="https://example.com",
    )[0]

    assert "recognized" in finding.description


def test_description_for_multiple_policies():
    finding = CORPFindingAnalyzer().analyze(
        analysis(CORPIndicatorType.MULTIPLE_POLICIES),
        target="https://example.com",
    )[0]

    assert "Multiple" in finding.description


def test_empty_analysis():
    findings = CORPFindingAnalyzer().analyze(
        CORPAnalysis(detected=False, indicators=()),
        target="https://example.com",
    )

    assert findings == []
