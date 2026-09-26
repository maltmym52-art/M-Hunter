import pytest

from m_hunter.analyzers.nosql_injection import (
    NoSQLInjectionAnalyzer,
)
from m_hunter.analyzers.nosql_injection_finding import (
    NoSQLInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding


def analyzer():
    return NoSQLInjectionAnalyzer()


def finding_analyzer():
    return NoSQLInjectionFindingAnalyzer()


def test_clean_analysis_creates_no_findings():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"username": "test"},
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert findings == []


def test_mongodb_operator_finding():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$ne": "invalid"},
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)
    assert "MongoDB" in findings[0].title


def test_mongodb_operator_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$eq": "admin"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-943"
    assert finding.owasp == "A03:2021"


def test_regex_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$regex": ".*"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-943"


def test_javascript_operator_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$where": "true"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.confidence == "Medium"


def test_dollar_prefix_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$custom": "value"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Low"


def test_dot_notation_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"user.role": "admin"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Low"
    assert finding.confidence == "Low"


def test_query_object_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"user": {"role": "admin"}},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Info"
    assert finding.confidence == "Low"


def test_database_error_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        response_text="MongoServerError",
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"


def test_mongodb_context_metadata():
    analysis = analyzer().analyze(
        "https://example.com",
        response_text="mongoose",
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Info"
    assert finding.confidence == "Low"


def test_endpoint_and_parameter_are_preserved():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$ne": "x"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
        endpoint="/api/login",
    )[0]

    assert finding.endpoint == "/api/login"
    assert finding.parameter == "$ne"


def test_target_is_preserved():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$ne": "x"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://target.example",
    )[0]

    assert finding.target == "https://target.example"


def test_evidence_is_present():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$ne": "x"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.evidence


def test_remediation_is_present():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$ne": "x"},
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.remediation
    assert "parameterized" in finding.remediation


def test_description_contains_disclaimer():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$ne": "x"},
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
            "$ne": "x",
            "$regex": ".*",
        },
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert len(findings) == 2


def test_analyze_alias():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$ne": "x"},
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
        query={"$ne": "x"},
    )

    with pytest.raises(ValueError):
        finding_analyzer().create_findings(
            analysis,
            "",
        )


def test_whitespace_target():
    analysis = analyzer().analyze(
        "https://example.com",
        query={"$ne": "x"},
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
            "$ne": "x",
            "$regex": ".*",
            "$where": "true",
        },
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert all(item.cwe == "CWE-943" for item in findings)


def test_all_findings_have_owasp():
    analysis = analyzer().analyze(
        "https://example.com",
        query={
            "$ne": "x",
            "$regex": ".*",
        },
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert all(item.owasp == "A03:2021" for item in findings)


def test_finding_ids_are_unique():
    analysis = analyzer().analyze(
        "https://example.com",
        query={
            "$ne": "x",
            "$regex": ".*",
        },
    )

    findings = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )

    assert findings[0].id != findings[1].id


def test_json_context_finding():
    analysis = analyzer().analyze(
        "https://example.com",
        content_type="application/json",
    )

    finding = finding_analyzer().create_findings(
        analysis,
        "https://example.com",
    )[0]

    assert finding.severity == "Info"
    assert finding.confidence == "Low"
