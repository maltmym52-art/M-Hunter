"""Execution requirements for analysis components."""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class AnalyzerCapabilities:
    """Describe data requirements and execution safety for an analyzer."""

    mode: Literal["passive", "active"] = "passive"
    requires_authorization: bool = False
    requires_request: bool = False
    requires_response: bool = False
    requires_context: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if self.mode not in {"passive", "active"}:
            raise ValueError("analyzer mode must be passive or active")
        if self.mode == "active" and not self.requires_authorization:
            raise ValueError("active analyzers must require authorization")
