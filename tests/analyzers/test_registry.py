import pytest

from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.metadata import MetadataAnalyzer
from m_hunter.analyzers.registry import AnalyzerRegistry
from m_hunter.core.response import HttpResponse


class CustomAnalyzer(BaseAnalyzer):
    name = "custom"
    description = "Custom analyzer"

    def analyze(self, response: HttpResponse) -> dict:
        return {
            "status_code": response.status_code,
        }


class AnotherAnalyzer(BaseAnalyzer):
    name = "another"
    description = "Another analyzer"

    def analyze(self, response: HttpResponse) -> dict:
        return {}


def test_registry_starts_empty():
    registry = AnalyzerRegistry()

    assert registry.count() == 0
    assert registry.names() == []
    assert registry.get_all() == []


def test_register_analyzer():
    registry = AnalyzerRegistry()
    analyzer = MetadataAnalyzer()

    registry.register(analyzer)

    assert registry.count() == 1
    assert registry.get("metadata") is analyzer


def test_register_multiple_analyzers():
    registry = AnalyzerRegistry()

    first = MetadataAnalyzer()
    second = CustomAnalyzer()

    registry.register(first)
    registry.register(second)

    assert registry.count() == 2
    assert registry.names() == [
        "metadata",
        "custom",
    ]


def test_get_returns_registered_analyzer():
    registry = AnalyzerRegistry()
    analyzer = CustomAnalyzer()

    registry.register(analyzer)

    assert registry.get("custom") is analyzer


def test_get_missing_analyzer_raises_key_error():
    registry = AnalyzerRegistry()

    with pytest.raises(
        KeyError,
        match="Analyzer not found: missing",
    ):
        registry.get("missing")


def test_duplicate_analyzer_registration_raises():
    registry = AnalyzerRegistry()

    registry.register(MetadataAnalyzer())

    with pytest.raises(
        ValueError,
        match="Analyzer already registered: metadata",
    ):
        registry.register(MetadataAnalyzer())


def test_invalid_analyzer_registration_raises():
    registry = AnalyzerRegistry()

    with pytest.raises(
        TypeError,
        match="BaseAnalyzer",
    ):
        registry.register(object())


def test_get_all_returns_registered_analyzers():
    registry = AnalyzerRegistry()

    first = MetadataAnalyzer()
    second = CustomAnalyzer()

    registry.register(first)
    registry.register(second)

    analyzers = registry.get_all()

    assert analyzers == [
        first,
        second,
    ]


def test_get_all_returns_copy_of_collection():
    registry = AnalyzerRegistry()

    analyzer = MetadataAnalyzer()
    registry.register(analyzer)

    analyzers = registry.get_all()
    analyzers.clear()

    assert registry.count() == 1
    assert registry.get("metadata") is analyzer


def test_names_returns_copy_of_names():
    registry = AnalyzerRegistry()

    registry.register(MetadataAnalyzer())

    names = registry.names()
    names.clear()

    assert registry.names() == ["metadata"]


def test_count_tracks_registered_analyzers():
    registry = AnalyzerRegistry()

    assert registry.count() == 0

    registry.register(MetadataAnalyzer())
    assert registry.count() == 1

    registry.register(CustomAnalyzer())
    assert registry.count() == 2


def test_clear_removes_all_analyzers():
    registry = AnalyzerRegistry()

    registry.register(MetadataAnalyzer())
    registry.register(CustomAnalyzer())

    registry.clear()

    assert registry.count() == 0
    assert registry.names() == []
    assert registry.get_all() == []


def test_registry_instances_are_independent():
    first = AnalyzerRegistry()
    second = AnalyzerRegistry()

    first.register(MetadataAnalyzer())

    assert first.count() == 1
    assert second.count() == 0


def test_registry_accepts_subclasses_of_base_analyzer():
    registry = AnalyzerRegistry()
    analyzer = CustomAnalyzer()

    registry.register(analyzer)

    assert registry.get("custom") is analyzer


def test_registered_analyzer_preserves_identity():
    registry = AnalyzerRegistry()
    analyzer = MetadataAnalyzer()

    registry.register(analyzer)

    assert registry.get_all()[0] is analyzer
