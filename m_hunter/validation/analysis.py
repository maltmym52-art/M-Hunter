"""Validation decisions for analyzer results."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class AnalysisDisposition(str, Enum):
    """Semantic outcome assigned to an analyzer result."""

    FINDING = "finding"
    INFORMATIONAL = "informational"
    INVALID = "invalid"


@dataclass(frozen=True)
class FindingCandidate:
    """Finding metadata explicitly supported by analysis and validation."""

    title: str | None = None
    severity: str | None = None
    confidence: str | None = None
    target: str | None = None
    endpoint: str | None = None
    parameter: str | None = None
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe: str | None = None
    owasp: str | None = None
    status: str = "open"
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalysisValidation:
    """A validator's semantic decision and optional Finding candidate."""

    disposition: AnalysisDisposition
    candidate: FindingCandidate | None = None
    errors: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def finding(
        cls,
        candidate: FindingCandidate,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> "AnalysisValidation":
        return cls(
            disposition=AnalysisDisposition.FINDING,
            candidate=candidate,
            metadata=metadata or {},
        )

    @classmethod
    def informational(
        cls,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> "AnalysisValidation":
        return cls(
            disposition=AnalysisDisposition.INFORMATIONAL,
            metadata=metadata or {},
        )

    @classmethod
    def invalid(
        cls,
        *errors: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> "AnalysisValidation":
        return cls(
            disposition=AnalysisDisposition.INVALID,
            errors=tuple(errors),
            metadata=metadata or {},
        )
