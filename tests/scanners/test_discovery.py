from m_hunter.scanners.base import BaseScanner
from m_hunter.scanners.discovery import ScannerDiscovery
from m_hunter.scanners.registry import ScannerRegistry


class ScannerStub(BaseScanner):
    name = "discovery_stub"
    description = "Discovery test scanner"

    def run(self, target):
        return []


def test_discovery_has_default_package():
    discovery = ScannerDiscovery()

    assert discovery.package_name == "m_hunter.scanners"


def test_discover_returns_scanner_classes():
    discovery = ScannerDiscovery()

    scanners = discovery.discover()

    assert scanners
    assert all(
        issubclass(scanner, BaseScanner)
        for scanner in scanners
    )


def test_discover_does_not_return_base_scanner():
    discovery = ScannerDiscovery()

    scanners = discovery.discover()

    assert BaseScanner not in scanners


def test_discover_returns_concrete_scanners():
    discovery = ScannerDiscovery()

    scanners = discovery.discover()

    names = {
        scanner.__name__
        for scanner in scanners
    }

    assert "ExampleScanner" in names
    assert "SecurityHeadersScanner" in names


def test_discovered_classes_are_defined_in_their_modules():
    discovery = ScannerDiscovery()

    scanners = discovery.discover()

    for scanner in scanners:
        assert scanner.__module__.startswith(
            "m_hunter.scanners."
        )


def test_register_all_registers_discovered_scanners():
    discovery = ScannerDiscovery()
    registry = ScannerRegistry()

    registered = discovery.register_all(registry)

    assert registered
    assert registry.count() == len(registered)


def test_register_all_returns_instances():
    discovery = ScannerDiscovery()
    registry = ScannerRegistry()

    registered = discovery.register_all(registry)

    assert all(
        isinstance(scanner, BaseScanner)
        for scanner in registered
    )


def test_register_all_registers_expected_scanners():
    discovery = ScannerDiscovery()
    registry = ScannerRegistry()

    discovery.register_all(registry)

    names = registry.names()

    assert "example" in names
    assert "security_headers" in names


def test_registered_scanners_are_retrievable():
    discovery = ScannerDiscovery()
    registry = ScannerRegistry()

    discovery.register_all(registry)

    example = registry.get("example")
    security_headers = registry.get("security_headers")

    assert isinstance(example, BaseScanner)
    assert isinstance(security_headers, BaseScanner)


def test_discovery_returns_new_class_list():
    discovery = ScannerDiscovery()

    first = discovery.discover()
    second = discovery.discover()

    assert first is not second
    assert first == second
