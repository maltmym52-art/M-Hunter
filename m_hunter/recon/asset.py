from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4


VALID_ASSET_TYPES = {
    "domain",
    "subdomain",
    "ip",
    "url",
    "endpoint",
    "javascript",
    "api",
}


@dataclass
class Asset:
    value: str
    asset_type: str

    id: str = field(default_factory=lambda: str(uuid4()))
    alive: bool = False
    source: str | None = None
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.value.strip():
            raise ValueError("value must not be empty")

        if self.asset_type not in VALID_ASSET_TYPES:
            raise ValueError(
                f"invalid asset type: {self.asset_type}"
            )

        self.value = self.value.strip()

    def mark_alive(self) -> None:
        self.alive = True

    def mark_dead(self) -> None:
        self.alive = False

    def add_metadata(self, key: str, value: str) -> None:
        if not key.strip():
            raise ValueError("metadata key must not be empty")

        self.metadata[key] = value

    def has_metadata(self, key: str) -> bool:
        return key in self.metadata

    def __hash__(self) -> int:
        return hash((self.asset_type, self.value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Asset):
            return NotImplemented

        return (
            self.asset_type,
            self.value,
        ) == (
            other.asset_type,
            other.value,
        )
