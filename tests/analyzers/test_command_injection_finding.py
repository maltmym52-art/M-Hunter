import pytest

from m_hunter.analyzers.command_injection import (
    CommandInjectionAnalyzer,
    CommandInjectionIndicator,
    CommandInjectionIndicatorType,
)
from m_hunter.analyzers.command_injection_finding import (
    CommandInjectionFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return CommandInjectionFindingAnalyzer()


@pytest.fixture
def command_analyzer():
    return CommandInjectionAnalyzer()


def test_empty_analysis_returns_no_findings(
    analyzer,
    command_analyzer,
):
    analysis = command_analyzer.analyze()

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert findings == []


def test_command_parameter_finding(
    analyzer,
    command_analyzer,
):
    analysis = command_analyzer.analyze(
        params={"cmd": "value"}
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
        endpoint="/run",
    )

    assert findings
    assert findings[0].severity == "Info"
    assert findings[0].confidence == "High"
    assert findings[0].cwe == "CWE-78"
    assert findings[0].owasp == "A03:2021"
    assert findings[0].target == "https://example.com"
    assert findings[0].endpoint == "/run"


@pytest.mark.parametrize(
    "indicator_type",
    list(CommandInjectionIndicatorType),
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
            CommandInjectionIndicatorType.COMMAND_PARAMETER,
            "Info",
            "High",
        ),
        (
            CommandInjectionIndicatorType.SHELL_PARAMETER,
            "Info",
            "High",
        ),
        (
            CommandInjectionIndicatorType.EXECUTION_PARAMETER,
            "Low",
            "High",
        ),
        (
            CommandInjectionIndicatorType.COMMAND_SEPARATOR,
            "Medium",
            "Medium",
        ),
        (
            CommandInjectionIndicatorType.PIPE_OPERATOR,
            "Medium",
            "Medium",
        ),
        (
            CommandInjectionIndicatorType.REDIRECTION_OPERATOR,
            "Medium",
            "Medium",
        ),
        (
            CommandInjectionIndicatorType.COMMAND_SUBSTITUTION,
            "High",
            "Medium",
        ),
        (
            CommandInjectionIndicatorType.BACKTICK_SUBSTITUTION,
            "High",
            "Medium",
        ),
        (
            CommandInjectionIndicatorType.COMMAND_OUTPUT,
            "High",
            "High",
        ),
        (
            CommandInjectionIndicatorType.EXECUTION_ERROR,
            "Medium",
            "High",
        ),
        (
            CommandInjectionIndicatorType.TIME_DELAY_INDICATOR,
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
    command_analyzer,
):
    analysis = command_analyzer.analyze(
        params={"cmd": "value;test"}
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert findings
    assert "value;test" in findings[0].evidence


def test_multiple_indicator_types_create_multiple_findings(
    analyzer,
    command_analyzer,
):
    analysis = command_analyzer.analyze(
        params={
            "cmd": "value;test|other",
        }
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert len(findings) >= 3


def test_findings_are_finding_objects(
    analyzer,
    command_analyzer,
):
    analysis = command_analyzer.analyze(
        params={"cmd": "value"}
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert all(isinstance(finding, Finding) for finding in findings)


def test_remediation_present(
    analyzer,
    command_analyzer,
):
    analysis = command_analyzer.analyze(
        params={"cmd": "value;test"}
    )

    findings = analyzer.analyze(
        analysis=analysis,
        target="https://example.com",
    )

    assert findings[0].remediation
    assert "allowlist" in findings[0].remediation.lower()


def test_description_contains_validation_disclaimer(
    analyzer,
    command_analyzer,
):
    analysis = command_analyzer.analyze(
        params={"cmd": "value;test"}
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
    command_analyzer,
    bad_target,
):
    analysis = command_analyzer.analyze()

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
    command_analyzer,
    bad_endpoint,
):
    analysis = command_analyzer.analyze()

    with pytest.raises(TypeError):
        analyzer.analyze(
            analysis=analysis,
            target="https://example.com",
            endpoint=bad_endpoint,
        )
