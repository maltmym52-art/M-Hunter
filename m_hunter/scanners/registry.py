from m_hunter.scanners.base import BaseScanner


class ScannerRegistry:
    def __init__(self):
        self._scanners: dict[str, BaseScanner] = {}

    def register(self, scanner: BaseScanner) -> None:
        if not isinstance(scanner, BaseScanner):
            raise TypeError("scanner must be an instance of BaseScanner")

        if scanner.name in self._scanners:
            raise ValueError(
                f"Scanner already registered: {scanner.name}"
            )

        self._scanners[scanner.name] = scanner

    def get(self, name: str) -> BaseScanner:
        try:
            return self._scanners[name]
        except KeyError as exc:
            raise KeyError(
                f"Scanner not found: {name}"
            ) from exc

    def get_all(self) -> list[BaseScanner]:
        return list(self._scanners.values())

    def names(self) -> list[str]:
        return list(self._scanners.keys())

    def count(self) -> int:
        return len(self._scanners)

    def clear(self) -> None:
        self._scanners.clear()
