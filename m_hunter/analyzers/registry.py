from m_hunter.analyzers.base import BaseAnalyzer


class AnalyzerRegistry:
    def __init__(self):
        self._analyzers: dict[str, BaseAnalyzer] = {}

    def register(self, analyzer: BaseAnalyzer) -> None:
        if not isinstance(analyzer, BaseAnalyzer):
            raise TypeError("analyzer must be an instance of BaseAnalyzer")

        if analyzer.name in self._analyzers:
            raise ValueError(
                f"Analyzer already registered: {analyzer.name}"
            )

        self._analyzers[analyzer.name] = analyzer

    def get(self, name: str) -> BaseAnalyzer:
        try:
            return self._analyzers[name]
        except KeyError as exc:
            raise KeyError(
                f"Analyzer not found: {name}"
            ) from exc

    def get_all(self) -> list[BaseAnalyzer]:
        return list(self._analyzers.values())

    def names(self) -> list[str]:
        return list(self._analyzers.keys())

    def count(self) -> int:
        return len(self._analyzers)

    def clear(self) -> None:
        self._analyzers.clear()
