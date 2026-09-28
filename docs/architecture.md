# M-Hunter Architecture

## Core layers and data flow

```text
CLI / optional GUI / future REST API
                 ↓
        ApplicationService
          ├─ Scope + authorization boundary
          ├─ Recon / HTTP / scanners
          └─ Analyzer → Validation → Evidence → core.Finding
                                      ↓
                          ScanExecutionResult
                                      ↓
                              Reporting

ScanExecutionResult + sanitized Evidence → optional AI Analyst Service
```

The application service owns workflow, scope enforcement, authorization,
cancellation checkpoints, lifecycle state, and errors. The CLI and desktop UI
are presentation clients. Both submit `ScanRequest` and consume
`ScanExecutionResult`; neither implements scanning or vulnerability logic.
Reporting uses the same `ReportService` and normalized, redacted report model.

## Application service and events

`ApplicationService` receives HTTP, tool, recon, scanner, analyzer, validation,
evidence, and scope dependencies. Active work is opt-in, requires an
`AuthorizationGrant`, and crosses the shared scope boundary. `ScanRequest`
supports a cooperative cancellation event checked at workflow boundaries.
Cancellation is a request; the service finalizes the scan at a safe checkpoint.

`ScanEventBus` publishes immutable transport-neutral lifecycle/progress events
(`ScanStarted`, `StageStarted`, `AssetDiscovered`, `RequestCompleted`,
`FindingCreated`, `ErrorOccurred`, `ScanCompleted`, and `ScanCancelled`). UI
listeners can subscribe without Qt coupling. Listener failures are isolated
from scan execution. Event text and target values are redacted.

## GUI

`m_hunter.gui.controller.GUIController` is headless-testable and accepts an
injected application service. It offers asynchronous scan submission,
cancellation, safe view data, and shared report rendering. It never launches
tools or sends requests itself. The optional PySide6 shell in `gui.app` renders
Dashboard, New Scan, Targets, Scope, Recon, Progress, Findings, Finding
Details, Evidence, Reports, Tools Status, and Settings pages. Install it with
`pip install m-hunter[gui]`; the core and CLI do not depend on Qt. The GUI
includes an optional AI Analyst page when a provider is injected; without one,
AI is reported unavailable and scans work normally. The entrypoint is
`m-hunter-gui`.
The Tools Status page asks ApplicationService for ToolRunner-backed availability
and version metadata; the UI does not execute binaries itself.

## Recon, analyzers, validation, and findings

Recon sources and scanners produce observations through the existing
application pipeline. Analyzers produce `AnalysisResult`; validators decide
whether a result is security-relevant; the finding pipeline converts only a
validated candidate into `core.Finding`. Adapters preserve legacy analyzer
interfaces. Scope checks remain authoritative for active operations.

EvidenceService associates evidence with findings and maintains raw and
sanitized forms. Reporting and GUI contracts consume sanitized exports only.
Renderers do not receive access to the raw evidence store representation.

## Reporting

`ReportService` normalizes `ScanExecutionResult` into versioned `ReportModel`
data, then renders JSON, Markdown, or HTML. CLI and GUI share this layer.
Report normalization removes raw-only fields and redacts credentials before
rendering or persistence.

## AI Analyst Service

`AIAnalysisService` is an optional service outside the mandatory scan path.
`AIProvider` is a provider-neutral contract; `MockAIProvider` supports local
tests. Provider input is an immutable snapshot built from normalized reports,
sanitized evidence exports, redacted HTTP observations, and Recon assets. The
provider receives no `ApplicationService`, ScopeManager, HTTP client, ToolRunner,
Finding object, or raw Evidence object. No provider/network dependency or API
key is required to use M-Hunter.

AI output is limited to `AIAnalysisNote` advisory annotations such as
explanation, correlation, prioritization rationale, remediation explanation,
duplicate suggestions, hypotheses, and analyst notes. Unknown finding IDs are
discarded, free-form output is redacted, malformed responses are marked
invalid, and provider exceptions return a failed AI result without changing a
scan.

**AI cannot create or confirm a Finding by itself.** An AI hypothesis is an
analyst note only. A real Finding must continue to pass through Analyzer →
Validation → Evidence → `core.Finding`. AI cannot set severity or confidence,
change Findings, mutate raw Evidence, perform active testing, send requests,
execute tools/payloads, or bypass ScopeManager or authorization.

## Security boundaries

- ScopeManager and the application service are the authority for active work.
- Passive analysis consumes supplied or already collected observations.
- The GUI delegates policy and execution to ApplicationService.
- External tools remain behind ToolRunner and the application scope boundary.
- AI receives only copied, immutable, sanitized material and has no execution
  capabilities.
- Findings are created by the validated finding pipeline, never by Reporting,
  GUI, or AI.
- Evidence/report/UI exports redact Authorization, Cookie, JWT, API keys,
  passwords, tokens, and sensitive query/form values.
