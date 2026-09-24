from dataclasses import dataclass, field

from m_hunter.core.finding import Finding


VALID_SEVERITIES = {
    "Info",
    "Low",
    "Medium",
    "High",
    "Critical",
}

VALID_CONFIDENCE = {
    "Low",
    "Medium",
    "High",
}


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return len(self.errors)


class FindingValidator:
    """Validates findings before they enter reporting workflows."""

    def validate(self, finding: Finding) -> ValidationResult:
        if not isinstance(finding, Finding):
            return ValidationResult(
                valid=False,
                errors=[
                    "finding must be an instance of Finding",
                ],
            )

        errors: list[str] = []

        if not finding.title.strip():
            errors.append("title must not be empty")

        if finding.severity not in VALID_SEVERITIES:
            errors.append(
                f"invalid severity: {finding.severity}"
            )

        if finding.confidence not in VALID_CONFIDENCE:
            errors.append(
                f"invalid confidence: {finding.confidence}"
            )

        if not finding.target.strip():
            errors.append("target must not be empty")

        if not finding.evidence.strip():
            errors.append("evidence must not be empty")

        return ValidationResult(
            valid=not errors,
            errors=errors,
        )

    def is_valid(self, finding: Finding) -> bool:
        return self.validate(finding).valid
