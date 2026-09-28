"""Transport-neutral request, status, issue, and result models for scans."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Event
from typing import Any, Mapping

from m_hunter.analyzers.result import AnalysisResult
from m_hunter.core.finding import Finding
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.core.scan import Scan
from m_hunter.recon.asset import Asset


class ScanStage(str, Enum):
    SCOPE = "scope"
    RECON = "recon"
    HTTP = "http"
    SCANNERS = "scanners"
    ANALYZERS = "analyzers"
    VALIDATION = "validation"
    EVIDENCE = "evidence"
    AGGREGATION = "aggregation"


class StageState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class ScanState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class AuthorizationGrant:
    """Explicit operator authorization required before active operations."""

    authorized: bool = False
    reference: str | None = None
    granted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ScanRequest:
    """Input to the application service, independent of CLI or GUI concerns."""

    target: str
    authorization: AuthorizationGrant = field(default_factory=AuthorizationGrant)
    active: bool = False
    recon: bool = False
    run_scanners: bool = True
    run_analyzers: bool = True
    scanner_names: tuple[str, ...] | None = None
    analyzer_names: tuple[str, ...] | None = None
    include_example_scanner: bool = False
    supplied_responses: Mapping[str, HttpResponse] = field(default_factory=dict)
    cancel_event: Event | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be a non-empty URL")
        if not isinstance(self.authorization, AuthorizationGrant):
            raise TypeError("authorization must be an AuthorizationGrant")
        self.target = self.target.strip()
        self.supplied_responses = dict(self.supplied_responses)
        self.metadata = dict(self.metadata)


@dataclass(frozen=True)
class ScanIssue:
    """A component failure or non-fatal condition observed during a scan."""

    component: str
    stage: ScanStage
    error: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    target: str | None = None
    endpoint: str | None = None
    level: str = "error"


@dataclass(frozen=True)
class ScanSecurityContext:
    """Authorization and scope facts captured for a single scan."""

    target: str
    in_scope: bool
    authorization_granted: bool
    active_enabled: bool
    authorization_reference: str | None = None


@dataclass
class StageRecord:
    stage: ScanStage
    state: StageState = StageState.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanStatistics:
    assets_discovered: int = 0
    http_requests: int = 0
    http_responses: int = 0
    scanners_run: int = 0
    analyzers_run: int = 0
    analyses_validated: int = 0
    findings: int = 0
    evidence_records: int = 0
    duplicates: int = 0
    errors: int = 0
    warnings: int = 0


@dataclass
class ScanExecutionResult:
    """Aggregated application-level outcome, suitable for CLI/API reporting."""

    scan: Scan
    state: ScanState = ScanState.PENDING
    assets: list[Asset] = field(default_factory=list)
    responses: dict[str, HttpResponse] = field(default_factory=dict)
    requests: dict[str, HttpRequest] = field(default_factory=dict)
    analyses: list[AnalysisResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
    stages: list[StageRecord] = field(default_factory=list)
    statistics: ScanStatistics = field(default_factory=ScanStatistics)
    security: ScanSecurityContext | None = None

    @property
    def errors(self) -> list[ScanIssue]:
        return [issue for issue in self.issues if issue.level == "error"]

    @property
    def warnings(self) -> list[ScanIssue]:
        return [issue for issue in self.issues if issue.level != "error"]
