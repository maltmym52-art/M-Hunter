from abc import ABC, abstractmethod
from typing import Any

from m_hunter.core.response import HttpResponse


class BaseAnalyzer(ABC):
    name: str = "base"
    description: str = "Base response analyzer"

    @abstractmethod
    def analyze(self, response: HttpResponse) -> dict[str, Any]:
        """Analyze an HTTP response and return structured results."""
        raise NotImplementedError
