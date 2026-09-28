"""Shared result container for analyzer execution."""

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class AnalysisResult:
    """Result of one analyzer run, preserving its original data type."""

    analyzer_name: str
    data: Any
    status: str = "success"
    errors: list[str] = field(default_factory=list)
    metadata: Mapping[str, Any] = field(default_factory=dict)
