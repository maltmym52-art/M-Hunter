from abc import ABC, abstractmethod

from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import DiscoverySource


class DNSResolver(ABC):
    """Base interface for DNS resolution."""

    @abstractmethod
    def resolve(
        self,
        hostname: str,
        record_type: str = "A",
    ) -> list[str]:
        """Resolve DNS records for a hostname."""
        raise NotImplementedError


class StaticDNSResolver(DNSResolver):
    """Static resolver used for testing and deterministic workflows."""

    def __init__(
        self,
        records: dict[tuple[str, str], list[str]] | None = None,
    ):
        self.records = {
            key: list(values)
            for key, values in (records or {}).items()
        }

    def resolve(
        self,
        hostname: str,
        record_type: str = "A",
    ) -> list[str]:
        return list(
            self.records.get(
                (hostname, record_type.upper()),
                [],
            )
        )


class DNSDiscoverySource(DiscoverySource):
    """Discovers DNS records and converts them into Assets."""

    name = "dns"

    RECORD_TYPES = (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "TXT",
    )

    def __init__(
        self,
        resolver: DNSResolver,
        record_types: tuple[str, ...] | None = None,
    ):
        if not isinstance(resolver, DNSResolver):
            raise TypeError(
                "resolver must be an instance of DNSResolver"
            )

        self.resolver = resolver

        self.record_types = tuple(
            record_type.upper()
            for record_type in (
                record_types
                if record_types is not None
                else self.RECORD_TYPES
            )
        )

        for record_type in self.record_types:
            if not record_type.strip():
                raise ValueError(
                    "record type must not be empty"
                )

    def discover(self, target: str) -> list[Asset]:
        target = target.strip()

        if not target:
            raise ValueError(
                "target must not be empty"
            )

        assets: list[Asset] = []
        seen: set[tuple[str, str]] = set()

        for record_type in self.record_types:
            values = self.resolver.resolve(
                target,
                record_type,
            )

            for value in values:
                value = value.strip()

                if not value:
                    continue

                value = value.rstrip(".")

                if not value:
                    continue

                asset_type = self._asset_type(
                    record_type
                )

                key = (
                    asset_type,
                    value,
                )

                if key in seen:
                    continue

                seen.add(key)

                assets.append(
                    Asset(
                        value=value,
                        asset_type=asset_type,
                        source=self.name,
                    )
                )

        return assets

    @staticmethod
    def _asset_type(record_type: str) -> str:
        mapping = {
            "A": "ip",
            "AAAA": "ip",
            "CNAME": "subdomain",
            "MX": "domain",
            "TXT": "domain",
        }

        return mapping.get(
            record_type.upper(),
            "domain",
        )
