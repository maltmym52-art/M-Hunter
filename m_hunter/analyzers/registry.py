from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.adapters import LegacyAnalyzerAdapter


class AnalyzerRegistry:
    def __init__(self):
        self._analyzers: dict[str, BaseAnalyzer] = {}

    def register(self, analyzer: BaseAnalyzer | object) -> None:
        """Register a unified analyzer or adapt a compatible legacy analyzer.

        BaseAnalyzer instances retain identity and existing behavior. Objects
        exposing ``analyze`` are wrapped without changing their public API.
        """
        if not isinstance(analyzer, BaseAnalyzer):
            if not callable(getattr(analyzer, "analyze", None)):
                raise TypeError(
                    "analyzer must be a BaseAnalyzer or expose a callable analyze method"
                )
            analyzer = LegacyAnalyzerAdapter(analyzer)

        if analyzer.name in self._analyzers:
            raise ValueError(
                f"Analyzer already registered: {analyzer.name}"
            )

        self._analyzers[analyzer.name] = analyzer

    def register_legacy(self, analyzer: object, *, invoke=None, name: str | None = None) -> BaseAnalyzer:
        """Register a legacy analyzer with an optional explicit context mapper."""
        adapter = LegacyAnalyzerAdapter(analyzer, invoke, name=name)
        self.register(adapter)
        return adapter

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
