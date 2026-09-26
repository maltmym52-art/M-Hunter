import pytest

from m_hunter.analyzers.prototype_pollution import PrototypePollutionAnalyzer
from m_hunter.analyzers.prototype_pollution_finding import (
    PrototypePollutionFindingAnalyzer,
)
from m_hunter.core.finding import Finding


def analyzer():
    return PrototypePollutionAnalyzer()


def finding_analyzer():
    return PrototypePollutionFindingAnalyzer()


def test_no_findings_for_clean_analysis():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"name": "test"},
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert findings == []


def test_proto_key_creates_finding():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert "__proto__" in findings[0].title


def test_constructor_key_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"constructor": "prototype"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-1321"
    assert finding.owasp == "A03:2021"


def test_prototype_key_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"prototype": "polluted"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-1321"


def test_nested_object_is_low_confidence():
    analysis = analyzer().analyze(
        "https://example.com",
        body={"user": {"name": "test"}},
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    nested = next(
        item for item in findings
        if "Nested Object" in item.title
    )

    assert nested.severity == "Info"
    assert nested.confidence == "Low"


def test_pollution_marker_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        response_text="polluted",
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-1321"


def test_endpoint_and_parameter_are_preserved():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
        endpoint="/api/profile",
    )[0]

    assert finding.endpoint == "/api/profile"
    assert finding.parameter == "__proto__"


def test_target_is_preserved():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )

    target = "https://target.example"
    finding = finding_analyzer().create_findings(
        analysis,
        target,
    )[0]

    assert finding.target == target


def test_evidence_is_preserved():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.evidence


def test_remediation_is_present():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.remediation
    assert "__proto__" in finding.remediation


def test_description_contains_validation_disclaimer():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert "does not prove" in finding.description


def test_multiple_indicators_create_multiple_findings():
    analysis = analyzer().analyze(
        "https://example.com",
        query={
            "__proto__": "polluted",
            "constructor": "prototype",
        },
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 2


def test_analyze_alias_matches_create_findings():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )

    first = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )
    second = finding_analyzer().analyze(
        analysis,
        "https://example.com",
    )

    assert len(first) == len(second)
    assert first[0].title == second[0].title


def test_invalid_analysis_type():
    with pytest.raises(TypeError):
        finding_analyzer().create_findings(
            object(),
            "https://example.com",
        )


def test_empty_target():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )

    with pytest.raises(ValueError):
        finding_analyzer().create_findings(
            analysis,
            "",
        )


def test_whitespace_target():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )

    with pytest.raises(ValueError):
        finding_analyzer().create_findings(
            analysis,
            "   ",
        )


def test_all_findings_have_cwe():
    analysis = analyzer().analyze(
        "https://example.com",
        query={
            "__proto__": "polluted",
            "constructor": "prototype",
            "prototype": "x",
        },
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert all(item.cwe == "CWE-1321" for item in findings)


def test_all_findings_have_owasp():
    analysis = analyzer().analyze(
        "https://example.com",
        query={
            "__proto__": "polluted",
            "constructor": "prototype",
        },
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert all(item.owasp == "A03:2021" for item in findings)


def test_javascript_context_finding():
    analysis = analyzer().analyze(
        "https://example.com/app.js",
        content_type="application/javascript",
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Info"
    assert finding.confidence == "Low"


def test_json_object_finding():
    analysis = analyzer().analyze(
        "https://example.com",
        body={"name": "test"},
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert any("JSON Object" in item.title for item in findings)


def test_finding_ids_are_unique():
    analysis = analyzer().analyze(
        "https://example.com",
        query={
            "__proto__": "polluted",
            "constructor": "prototype",
        },
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert findings[0].id != findings[1].id
