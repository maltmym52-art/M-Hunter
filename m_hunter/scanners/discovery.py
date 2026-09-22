import importlib
import inspect
import pkgutil

from m_hunter.scanners.base import BaseScanner
from m_hunter.scanners.registry import ScannerRegistry


class ScannerDiscovery:
    def __init__(
        self,
        package_name: str = "m_hunter.scanners",
    ):
        self.package_name = package_name

    def discover(self) -> list[type[BaseScanner]]:
        package = importlib.import_module(self.package_name)

        discovered: list[type[BaseScanner]] = []

        for module_info in pkgutil.iter_modules(
            package.__path__,
            package.__name__ + ".",
        ):
            module = importlib.import_module(module_info.name)

            for _, obj in inspect.getmembers(
                module,
                inspect.isclass,
            ):
                if not issubclass(obj, BaseScanner):
                    continue

                if obj is BaseScanner:
                    continue

                if obj.__module__ != module.__name__:
                    continue

                discovered.append(obj)

        return discovered

    def register_all(
        self,
        registry: ScannerRegistry,
    ) -> list[BaseScanner]:
        registered: list[BaseScanner] = []

        for scanner_class in self.discover():
            scanner = scanner_class()
            registry.register(scanner)
            registered.append(scanner)

        return registered
