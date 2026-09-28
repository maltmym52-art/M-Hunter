"""Provider contract; concrete network providers can be added independently."""

from typing import Protocol

from m_hunter.ai.models import AIAnalysisRequest


class AIProvider(Protocol):
    """Provider receives sanitized analysis data and returns advisory output."""

    name: str

    def analyze(self, request: AIAnalysisRequest) -> object:
        """Return untrusted provider output; the service validates its shape."""


class MockAIProvider:
    """Deterministic local provider for tests and offline development."""

    name = "mock"

    def __init__(self, response: object | None = None) -> None:
        self.response = response
        self.requests: list[AIAnalysisRequest] = []

    def analyze(self, request: AIAnalysisRequest) -> object:
        self.requests.append(request)
        return self.response if self.response is not None else {
            "notes": [{"kind": "summary", "text": "Review the validated scan evidence."}]
        }
