"""Transport contracts for CLI features owned by later application layers."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal


ReportFormat = Literal["json", "markdown", "html"]


@dataclass(frozen=True)
class ReportRequest:
    """Validated input/output intent for a future Reporting service."""

    input_path: Path
    format: ReportFormat = "json"
    output_path: Path | None = None
