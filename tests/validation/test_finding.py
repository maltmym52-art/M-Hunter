import pytest

from m_hunter.core.finding import Finding
from m_hunter.validation.finding import (
    FindingValidator,
    VALID_CONFIDENCE,
    VALID_SEVERITIES,
    ValidationResult,
)


def make_finding(**overrides) -> Finding:
    values = {
        "title": "Test Finding",
        "severity": "Medium",
        "confidence": "High",
        "target": "https://example.com",
        "evidence": "Security evidence",
    }

    values.update(overrides)

    return Finding(**values)


def test_validation_result_is_valid():
    result = ValidationResult(valid=True)

    assert result.valid is True
    assert result.errors == []
    assert result.error_count == 0


def test_validation_result_contains_errors():
    result = ValidationResult(
        valid=False,
        errors=[
            "first error",
            "second error",
        ],
    )

    assert result.valid is False
    assert result.error_count == 2


def test_validator_can_be_created():
    validator = FindingValidator()

    assert isinstance(validator, FindingValidator)


def test_valid_finding_passes_validation():
    validator = FindingValidator()

    result = validator.validate(
        make_finding()
    )

    assert result.valid is True
    assert result.errors == []


def test_is_valid_returns_true_for_valid_finding():
    validator = FindingValidator()

    assert validator.is_valid(
        make_finding()
    ) is True


def test_invalid_object_fails_validation():
    validator = FindingValidator()

    result = validator.validate(
        "not a finding"
    )

    assert result.valid is False
    assert result.errors == [
        "finding must be an instance of Finding",
    ]


@pytest.mark.parametrize(
    "severity",
    sorted(VALID_SEVERITIES),
)
def test_valid_severities_are_accepted(severity):
    validator = FindingValidator()

    finding = make_finding(
        severity=severity,
    )

    assert validator.is_valid(finding) is True


@pytest.mark.parametrize(
    "confidence",
    sorted(VALID_CONFIDENCE),
)
def test_valid_confidence_values_are_accepted(confidence):
    validator = FindingValidator()

    finding = make_finding(
        confidence=confidence,
    )

    assert validator.is_valid(finding) is True


def test_invalid_severity_fails_validation():
    validator = FindingValidator()

    result = validator.validate(
        make_finding(
            severity="Unknown",
        )
    )

    assert result.valid is False
    assert result.errors == [
        "invalid severity: Unknown",
    ]


def test_invalid_confidence_fails_validation():
    validator = FindingValidator()

    result = validator.validate(
        make_finding(
            confidence="Unknown",
        )
    )

    assert result.valid is False
    assert result.errors == [
        "invalid confidence: Unknown",
    ]


def test_empty_title_fails_validation():
    validator = FindingValidator()

    result = validator.validate(
        make_finding(
            title="",
        )
    )

    assert result.valid is False
    assert "title must not be empty" in result.errors


def test_whitespace_title_fails_validation():
    validator = FindingValidator()

    result = validator.validate(
        make_finding(
            title="   ",
        )
    )

    assert result.valid is False
    assert "title must not be empty" in result.errors


def test_empty_target_fails_validation():
    validator = FindingValidator()

    result = validator.validate(
        make_finding(
            target="",
        )
    )

    assert result.valid is False
    assert "target must not be empty" in result.errors


def test_whitespace_target_fails_validation():
    validator = FindingValidator()

    result = validator.validate(
        make_finding(
            target="   ",
        )
    )

    assert result.valid is False
    assert "target must not be empty" in result.errors


def test_empty_evidence_fails_validation():
    validator = FindingValidator()

    result = validator.validate(
        make_finding(
            evidence="",
        )
    )

    assert result.valid is False
    assert "evidence must not be empty" in result.errors


def test_whitespace_evidence_fails_validation():
    validator = FindingValidator()

    result = validator.validate(
        make_finding(
            evidence="   ",
        )
    )

    assert result.valid is False
    assert "evidence must not be empty" in result.errors


def test_multiple_validation_errors_are_reported():
    validator = FindingValidator()

    result = validator.validate(
        make_finding(
            title="",
            severity="Invalid",
            confidence="Invalid",
            target="",
            evidence="",
        )
    )

    assert result.valid is False

    assert result.errors == [
        "title must not be empty",
        "invalid severity: Invalid",
        "invalid confidence: Invalid",
        "target must not be empty",
        "evidence must not be empty",
    ]


def test_validation_does_not_modify_finding():
    validator = FindingValidator()

    finding = make_finding()

    original = (
        finding.title,
        finding.severity,
        finding.confidence,
        finding.target,
        finding.evidence,
    )

    validator.validate(finding)

    assert (
        finding.title,
        finding.severity,
        finding.confidence,
        finding.target,
        finding.evidence,
    ) == original
