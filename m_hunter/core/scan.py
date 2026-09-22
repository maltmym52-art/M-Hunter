from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4

from m_hunter.core.target import Target


@dataclass
class Scan:
    target: Target
    id: str = field(default_factory=lambda: str(uuid4()))
    status: str = "pending"
    started_at: datetime | None = None
    finished_at: datetime | None = None

    def start(self) -> None:
        self.status = "running"
        self.started_at = datetime.now()

    def finish(self) -> None:
        self.status = "completed"
        self.finished_at = datetime.now()
