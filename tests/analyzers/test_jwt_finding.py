import pytest

from m_hunter.analyzers.jwt import (
    JWTAnalysis,
    JWTAnalyzer,
    JWTIndicator,
    JWTIndicatorType,
)
from m_hunter.analyzers.jwt_finding import JWTFindingAnalyzer
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return JWTFindingAnalyzer()


@pytest.fixture
def jwt_analyzer():
    return JWTAnalyzer()


def make_analysis(*types):
    indicators = tuple(
        JWTIndicator(
            type=indicator_type,
            evidence=f"Evidence for {indicator_type.value}",
            name="alg",
            value="HS256",
        )
        for indicator_type in types
    )

    return JWTAnalysis(indicators=indicators)


def test_empty_analysis_returns_no_findings(analyzer):
    result = analyzer.analyze(
        analysis=JWTAnalysis(indicators=()),
        target="https://example.com",
    )

    assert result == []


def test_requires_jwt_analysis(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            analysis="invalid",
            target="https://example.com",
        )


def test_requires_target(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            analysis=JWTAnalysis(indicators=()),
            target="",
        )


def test_endpoint_must_be_string(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            analysis=JWTAnalysis(indicators=()),
            target="https://example.com",
            endpoint=123,
        )


@pytest.mark.parametrize(
    "indicator_type",
    list(JWTIndicatorType),
)
def test_each_indicator_generates_finding(analyzer, indicator_type):
    findings = analyzer.analyze(
        analysis=make_analysis(indicator_type),
        target="https://example.com",
        endpoint="/login",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.target == "https://example.com"
    assert finding.endpoint == "/login"
    assert finding.title
    assert finding.severity
    assert finding.confidence
    assert finding.description
    assert finding.evidence
    assert finding.remediation


def test_none_algorithm_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.NONE_ALGORITHM,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Critical"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-327"
    assert finding.owasp == "OWASP A07:2021"


def test_weak_algorithm_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.WEAK_ALGORITHM,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-327"


def test_missing_expiration_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.MISSING_EXPIRATION,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-613"


def test_long_lived_token_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.LONG_LIVED_TOKEN,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-613"


def test_jwt_in_url_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.JWT_IN_URL,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-598"


def test_sensitive_data_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.SENSITIVE_DATA,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "High"
    assert finding.confidence == "High"
    assert finding.cwe == "CWE-200"


def test_invalid_structure_metadata(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.INVALID_STRUCTURE,
        ),
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"


def test_multiple_types_create_multiple_findings(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.JWT,
            JWTIndicatorType.WEAK_ALGORITHM,
            JWTIndicatorType.JWT_IN_URL,
        ),
        target="https://example.com",
    )

    assert len(findings) == 3

    assert {
        finding.title
        for finding in findings
    } == {
        "JWT detected",
        "Weak JWT algorithm indicator detected",
        "JWT exposed in URL",
    }


def test_same_type_is_grouped(analyzer):
    analysis = JWTAnalysis(
        indicators=(
            JWTIndicator(
                type=JWTIndicatorType.JWT,
                evidence="First JWT",
                value="token-one",
            ),
            JWTIndicator(
                type=JWTIndicatorType.JWT,
                evidence="Second JWT",
                value="token-two",
            ),
        )
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert len(findings) == 1
    assert "First JWT" in findings[0].evidence
    assert "Second JWT" in findings[0].evidence


def test_indicator_details_are_in_evidence(analyzer):
    analysis = JWTAnalysis(
        indicators=(
            JWTIndicator(
                type=JWTIndicatorType.ALGORITHM,
                evidence="Algorithm detected",
                name="alg",
                value="HS256",
            ),
        )
    )

    finding = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )[0]

    assert "Algorithm detected" in finding.evidence
    assert "name=alg" in finding.evidence
    assert "value=HS256" in finding.evidence


def test_description_contains_validation_disclaimer(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.WEAK_ALGORITHM,
        ),
        target="https://example.com",
    )[0]

    assert "does not by itself prove a vulnerability" in finding.description


def test_remediation_is_present(analyzer):
    finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.JWT,
        ),
        target="https://example.com",
    )[0]

    assert "Validate JWT signatures" in finding.remediation
    assert "token expiration" in finding.remediation


def test_all_supported_types_have_metadata(analyzer):
    assert set(analyzer.METADATA) == set(JWTIndicatorType)


def test_findings_have_unique_ids(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.JWT,
            JWTIndicatorType.WEAK_ALGORITHM,
        ),
        target="https://example.com",
    )

    assert len({finding.id for finding in findings}) == 2


def test_real_analyzer_output_can_be_converted(
    analyzer,
    jwt_analyzer,
):
    analysis = jwt_analyzer.analyze(
        algorithm="none",
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
        endpoint="/login",
    )

    assert findings
    assert all(
        isinstance(finding, Finding)
        for finding in findings
    )


def test_all_findings_have_target_and_endpoint(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.JWT,
            JWTIndicatorType.JWT_IN_COOKIE,
        ),
        target="https://example.com",
        endpoint="/api/auth",
    )

    assert all(
        finding.target == "https://example.com"
        for finding in findings
    )

    assert all(
        finding.endpoint == "/api/auth"
        for finding in findings
    )


def test_missing_claim_findings_have_cwe(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.MISSING_ISSUER,
            JWTIndicatorType.MISSING_AUDIENCE,
            JWTIndicatorType.MISSING_NOT_BEFORE,
            JWTIndicatorType.MISSING_ISSUED_AT,
        ),
        target="https://example.com",
    )

    assert all(finding.cwe for finding in findings)


def test_transport_indicators_are_not_automatically_critical(analyzer):
    findings = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.JWT_IN_COOKIE,
            JWTIndicatorType.JWT_IN_AUTHORIZATION,
        ),
        target="https://example.com",
    )

    assert all(
        finding.severity == "Info"
        for finding in findings
    )


def test_none_algorithm_has_strongest_metadata(analyzer):
    none_finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.NONE_ALGORITHM,
        ),
        target="https://example.com",
    )[0]

    weak_finding = analyzer.analyze(
        analysis=make_analysis(
            JWTIndicatorType.WEAK_ALGORITHM,
        ),
        target="https://example.com",
    )[0]

    assert none_finding.severity == "Critical"
    assert weak_finding.severity == "High"
