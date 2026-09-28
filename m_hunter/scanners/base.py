from abc import ABC, abstractmethod

from m_hunter.core.finding import Finding
from m_hunter.core.target import Target


class BaseScanner(ABC):
    name: str = "base"
    description: str = "Base scanner"
    scope_aware: bool = False
    uses_http: bool = False

    @abstractmethod
    def run(self, target: Target) -> list[Finding]:
        """Run the scanner against the target."""
        raise NotImplementedError
