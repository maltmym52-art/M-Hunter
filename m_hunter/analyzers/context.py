"""Shared input context for analyzer execution."""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.core.target import Target


@dataclass(frozen=True)
class AnalysisContext:
    """Optional request, response, and auxiliary inputs for an analyzer.

    ``options`` contains analyzer-specific inputs, while ``metadata`` carries
    execution information. Both mappings are copied and exposed read-only.
    """

    response: HttpResponse | None = None
    content: str | bytes | None = None
    request_url: str | None = None
    target: Target | str | None = None
    request: HttpRequest | None = None
    options: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "options", MappingProxyType(dict(self.options))
        )
        object.__setattr__(
            self, "metadata", MappingProxyType(dict(self.metadata))
        )
