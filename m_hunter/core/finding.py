from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4


@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    target: str

    id: str = field(default_factory=lambda: str(uuid4()))
    endpoint: str | None = None
    parameter: str | None = None
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe: str | None = None
    owasp: str | None = None
    status: str = "open"
    created_at: datetime = field(default_factory=datetime.now)
