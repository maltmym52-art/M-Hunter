import pytest

from m_hunter.analyzers.ldap_injection import (
    LDAPInjectionAnalyzer,
    LDAPInjectionIndicatorType,
)
from m_hunter.analyzers.ldap_injection_finding import (
    LDAPInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return LDAPInjectionFindingAnalyzer()


@pytest.fixture
def ldap_analyzer():
    return LDAPInjectionAnalyzer()


def test_empty_analysis_returns_no_findings(
    analyzer,
    ldap_analyzer,
):
    analysis = ldap_analyzer.analyze()

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert findings == []


def test_ldap_parameter_finding(
    analyzer,
    ldap_analyzer,
):
    analysis = ldap_analyzer.analyze(
        params={"ldap": "value"}
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
        endpoint="/search",
    )

    assert findings
    assert findings[0].severity == "Info"
    assert findings[0].confidence == "High"
    assert findings[0].cwe == "CWE-90"
    assert findings[0].owasp == "A03:2021"
    assert findings[0].target == "https://example.com"
    assert findings[0].endpoint == "/search"


@pytest.mark.parametrize(
    "indicator_type",
    list(LDAPInjectionIndicatorType),
)
def test_all_indicator_types_have_metadata(
    analyzer,
    indicator_type,
):
    assert indicator_type in analyzer.METADATA


@pytest.mark.parametrize(
    ("indicator_type", "severity", "confidence"),
    [
        (
            LDAPInjectionIndicatorType.LDAP_PARAMETER,
            "Info",
            "High",
        ),
        (
            LDAPInjectionIndicatorType.FILTER_PARAMETER,
            "Info",
            "High",
        ),
        (
            LDAPInjectionIndicatorType.SEARCH_PARAMETER,
            "Info",
            "High",
        ),
        (
            LDAPInjectionIndicatorType.FILTER_SYNTAX,
            "Medium",
            "Medium",
        ),
        (
            LDAPInjectionIndicatorType.WILDCARD,
            "Low",
            "Medium",
        ),
        (
            LDAPInjectionIndicatorType.GROUPING_OPERATOR,
            "Medium",
            "Medium",
        ),
        (
            LDAPInjectionIndicatorType.LOGICAL_OPERATOR,
            "Medium",
            "Medium",
        ),
        (
            LDAPInjectionIndicatorType.ATTRIBUTE_OPERATOR,
            "Medium",
            "Medium",
        ),
        (
            LDAPInjectionIndicatorType.LDAP_ESCAPE_SEQUENCE,
            "Medium",
            "Medium",
        ),
        (
            LDAPInjectionIndicatorType.LDAP_ERROR,
            "Medium",
            "High",
        ),
        (
            LDAPInjectionIndicatorType.LDAP_RESULT,
            "Medium",
            "Medium",
        ),
        (
            LDAPInjectionIndicatorType.USER_CONTROLLED_FILTER,
            "High",
            "Medium",
        ),
    ],
)
def test_metadata_severity_and_confidence(
    analyzer,
    indicator_type,
    severity,
    confidence,
):
    assert analyzer.METADATA[indicator_type][1] == severity
    assert analyzer.METADATA[indicator_type][2] == confidence


def test_evidence_contains_value(
    analyzer,
    ldap_analyzer,
):
    analysis = ldap_analyzer.analyze(
        params={"filter": "(uid=admin)"}
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert findings
    assert "(uid=admin)" in findings[0].evidence


def test_multiple_indicator_types_create_multiple_findings(
    analyzer,
    ldap_analyzer,
):
    analysis = ldap_analyzer.analyze(
        params={
            "filter": "(&(uid=admin)(objectClass=*))"
        }
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert len(findings) >= 4


def test_findings_are_finding_objects(
    analyzer,
    ldap_analyzer,
):
    analysis = ldap_analyzer.analyze(
        params={"filter": "(uid=admin)"}
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert all(isinstance(finding, Finding) for finding in findings)


def test_remediation_present(
    analyzer,
    ldap_analyzer,
):
    analysis = ldap_analyzer.analyze(
        params={"filter": "(uid=admin)"}
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert findings[0].remediation
    assert "input" in findings[0].remediation.lower()


def test_description_contains_validation_disclaimer(
    analyzer,
    ldap_analyzer,
):
    analysis = ldap_analyzer.analyze(
        params={"filter": "(uid=admin)"}
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert "does not prove" in findings[0].description.lower()


def test_invalid_analysis(
    analyzer,
):
    with pytest.raises(TypeError):
        analyzer.analyze(
            analysis=None,
            target="https://example.com",
        )


@pytest.mark.parametrize(
    "bad_target",
    [None, "", "   "],
)
def test_invalid_target(
    analyzer,
    ldap_analyzer,
    bad_target,
):
    analysis = ldap_analyzer.analyze()

    with pytest.raises(ValueError):
        analyzer.analyze(
            analysis=analysis,
            target=bad_target,
        )


@pytest.mark.parametrize(
    "bad_endpoint",
    [123, [], {}],
)
def test_invalid_endpoint(
    analyzer,
    ldap_analyzer,
    bad_endpoint,
):
    analysis = ldap_analyzer.analyze()

    with pytest.raises(TypeError):
        analyzer.analyze(
            analysis=analysis,
            target="https://example.com",
            endpoint=bad_endpoint,
        )
