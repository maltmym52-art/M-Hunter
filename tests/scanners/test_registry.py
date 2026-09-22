import pytest

from m_hunter.core.finding import Finding
from m_hunter.core.target import Target
from m_hunter.scanners.base import BaseScanner
from m_hunter.scanners.registry import ScannerRegistry


class ScannerStub(BaseScanner):
    name = "stub"
    description = "Stub scanner"

    def run(self, target: Target) -> list[Finding]:
        return []


class AnotherScannerStub(BaseScanner):
    name = "another"
    description = "Another stub scanner"

    def run(self, target: Target) -> list[Finding]:
        return []


class DuplicateScannerStub(BaseScanner):
    name = "stub"
    description = "Duplicate scanner"

    def run(self, target: Target) -> list[Finding]:
        return []


def test_registry_starts_empty():
    registry = ScannerRegistry()

    assert registry.count() == 0
    assert registry.names() == []
    assert registry.get_all() == []


def test_register_scanner():
    registry = ScannerRegistry()
    scanner = ScannerStub()

    registry.register(scanner)

    assert registry.count() == 1
    assert registry.names() == ["stub"]
    assert registry.get("stub") is scanner


def test_register_multiple_scanners():
    registry = ScannerRegistry()

    scanner_one = ScannerStub()
    scanner_two = AnotherScannerStub()

    registry.register(scanner_one)
    registry.register(scanner_two)

    assert registry.count() == 2
    assert registry.names() == [
        "stub",
        "another",
    ]
    assert registry.get_all() == [
        scanner_one,
        scanner_two,
    ]


def test_get_returns_registered_scanner():
    registry = ScannerRegistry()
    scanner = ScannerStub()

    registry.register(scanner)

    result = registry.get("stub")

    assert result is scanner


def test_get_unknown_scanner_raises_error():
    registry = ScannerRegistry()

    with pytest.raises(KeyError, match="Scanner not found: unknown"):
        registry.get("unknown")


def test_duplicate_scanner_registration_raises_error():
    registry = ScannerRegistry()

    registry.register(ScannerStub())

    with pytest.raises(
        ValueError,
        match="Scanner already registered: stub",
    ):
        registry.register(DuplicateScannerStub())


def test_register_invalid_object_raises_type_error():
    registry = ScannerRegistry()

    with pytest.raises(
        TypeError,
        match="scanner must be an instance of BaseScanner",
    ):
        registry.register(object())


def test_get_all_returns_copy():
    registry = ScannerRegistry()
    scanner = ScannerStub()

    registry.register(scanner)

    scanners = registry.get_all()
    scanners.clear()

    assert registry.count() == 1
    assert registry.get("stub") is scanner


def test_names_returns_copy():
    registry = ScannerRegistry()
    registry.register(ScannerStub())

    names = registry.names()
    names.clear()

    assert registry.names() == ["stub"]


def test_clear_registry():
    registry = ScannerRegistry()

    registry.register(ScannerStub())
    registry.register(AnotherScannerStub())

    assert registry.count() == 2

    registry.clear()

    assert registry.count() == 0
    assert registry.names() == []
    assert registry.get_all() == []


def test_registry_can_be_reused_after_clear():
    registry = ScannerRegistry()

    scanner = ScannerStub()

    registry.register(scanner)
    registry.clear()
    registry.register(scanner)

    assert registry.count() == 1
    assert registry.get("stub") is scanner
