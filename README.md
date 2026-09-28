# M-Hunter

**M-Hunter** is a modular Python platform for authorized web-security research.
It combines passive HTTP analysis, scoped Recon integrations, validation,
redacted evidence, Findings, and JSON/Markdown/HTML reports behind one
`ApplicationService`. The CLI is the supported primary interface; an optional
PySide6 desktop shell and a provider-neutral AI analyst interface are also
available.

> **Coverage note:** M-Hunter is an early `0.1.0` release, not a replacement for
> a mature DAST platform. Many vulnerability modules and specialized pipelines
> exist, but that does not mean each is connected end to end or safe to run
> automatically. See [`docs/security-coverage-matrix.md`](docs/security-coverage-matrix.md)
> for the verified state by category.

## Features

- Shared orchestration via `ApplicationService` for CLI and GUI clients.
- Passive analysis of supplied or already collected HTTP requests and responses.
- Central scope and explicit-authorization checks before active operations.
- Analyzer adapters, validation decisions, canonical `core.Finding`, and
  sanitized Evidence records.
- Deterministic JSON, readable Markdown, and self-contained HTML reporting.
- Optional Recon integrations for Subfinder, Amass, httpx, Nmap, ffuf, and
  Nuclei. External binaries are not core install requirements.
- Optional PySide6 desktop UI; the CLI remains usable without Qt.
- Optional AI analyst contracts and a local mock provider. No API key or
  network AI provider is required.

## Architecture

```text
CLI / optional GUI / future API
              ↓
      ApplicationService
              ↓
Scope → Recon → HTTP → Scanners / Analyzers
                         ↓
          AnalysisResult → Validation
                         ↓
       Evidence → core.Finding → Report

             optional AI Analyst
       (sanitized advisory input only)
```

The GUI and CLI do not implement vulnerability checks. See
[`docs/architecture.md`](docs/architecture.md) for layers, events, cancellation,
and security boundaries.

## Installation

Requires Python 3.11 or newer. Install the core package in a virtual
environment:

```bash
python -m venv .venv
```

Linux / Kali:

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
m-hunter --help
```

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
m-hunter --help
```

The package uses Typer, Rich, and HTTPX. Desktop dependencies are optional:

```bash
python -m pip install '.[gui]'
m-hunter-gui
```

The GUI requires a desktop environment to display its window. Its controller
and architecture tests are headless and do not require PySide6 or a display
server.

## CLI

```text
m-hunter                 Show the banner
m-hunter --help          List commands
m-hunter version         Show the version
m-hunter scan URL        Run the default passive workflow
m-hunter recon URL       Run configured Recon sources
m-hunter analyze URL --input response.json
m-hunter report report.json --format json|markdown|html
m-hunter tools           Show optional tool availability
```

Example passive scan and report:

```bash
m-hunter scan https://authorized.example/ --passive --format json --output scan.json
m-hunter report scan.json --format html --output scan.html
```

Active work must be explicitly enabled and include an authorization reference:

```bash
m-hunter scan https://authorized.example/ --active \
  --authorization-reference "approved-test-123"
```

An authorization reference is an operator assertion; it does not grant access
to targets outside scope. ApplicationService and ScopeManager enforce the
configured scope. Active scans and external active tools are off by default.
The ExampleScanner is also disabled unless explicitly opted into for testing.

`analyze` accepts a previously captured response JSON and performs no network
request. For example:

```json
{"status_code": 200, "url": "https://authorized.example/", "headers": {"Content-Type": "text/html"}, "body": "<html>...</html>"}
```

## Recon tools

The `tools` command reports availability and, when available, version metadata
for Subfinder, Amass, httpx, Nmap, ffuf, and Nuclei. These binaries are optional
and are never installed by M-Hunter. Passive Recon defaults are conservative;
choose sources explicitly when appropriate. Nmap, ffuf, and active Nuclei use
require explicit active mode and authorization through the application scope
boundary. Never point them at systems without permission.

Recon integration tests use fake runners or local fixtures. This repository's
release checks do not run external scanning tools against real targets.

## Security analysis coverage

The repository contains analyzer/validator modules across areas including XSS,
injection classes, access control, API and identity protocols, cache behavior,
HTTP security headers, cookies, TLS, WebSocket, and protocol metadata. Their
presence is not a promise of automatic or end-to-end detection. In `0.1.0`, the
default CLI configures baseline security headers, cookie security, Cache-Control,
and metadata analyzers; findings still depend on their validators and available
observations. XSS reflection can be analyzed from supplied request/response
context, but reflection alone is not proof of exploitability.

Consult the [security coverage matrix](docs/security-coverage-matrix.md) for
per-category adapter, validation, Evidence, mode, and E2E status. Most
category-specific legacy validation pipelines are retained for compatibility
and are not automatically unified into the default scan path.

## Passive and active modes

- **Passive:** inspect supplied or already collected responses, headers,
  cookies, policies, and content without sending additional requests.
- **Active:** requests, scanner actions, payloads, or validation probes. Active
  behavior is opt-in, requires an `AuthorizationGrant`, and must pass through
  ScopeManager. An analyzer or AI provider cannot bypass that boundary.

## Findings, Evidence, and reports

An Analyzer returns analysis; a Validator decides whether it supports a
security Finding; the central conversion path creates `core.Finding`. Evidence
keeps raw and sanitized representations separately. CLI output, GUI views, AI
inputs, and reports use sanitized exports. Credentials and common token,
cookie, password, and sensitive-parameter values are redacted.

Supported formats:

- JSON for structured automation.
- Markdown for human-readable review.
- HTML for local, self-contained viewing.

## GUI

Install the optional extra, then run `m-hunter-gui`. The GUI shell provides
Dashboard, New Scan, Targets, Scope, Recon, Progress, Findings, Finding
Details, Evidence, Reports, Tools Status, Settings, and AI Analyst views. It
submits requests to ApplicationService and uses the shared Reporting service;
it does not launch subprocesses or implement scan policy.

## AI Analyst

AI analysis is optional and separate from scan execution. Providers receive
immutable, redacted snapshots of findings, sanitized Evidence, HTTP observations,
Recon assets, and scan summaries. The package includes a mock provider for
offline use and testing, but no network provider or API key configuration.

AI can return explanations, correlation/prioritization rationale, remediation
explanations, duplicate suggestions, hypotheses, and analyst notes. **AI cannot
create or confirm a Finding**, set severity/confidence, mutate Evidence, send
requests, execute tools, or perform active testing. An AI hypothesis remains an
analyst note; any Finding must pass through Analyzer → Validation → Evidence →
`core.Finding`.

## Testing

Run tests with:

```bash
python -m pytest
```

Release and integration tests use fake/local HTTP, Recon, and AI dependencies.
They do not require a display server, AI credentials, or external security
tools.

## Project structure

| Path | Purpose |
|---|---|
| `m_hunter/application/` | ApplicationService, request/results, scope boundary, default composition |
| `m_hunter/core/` | Scan, target, HTTP primitives, canonical Finding |
| `m_hunter/analyzers/`, `validation/` | Analysis contracts, legacy adapters, validators |
| `m_hunter/evidence/`, `findings/` | Redacted Evidence capture and validated Finding conversion |
| `m_hunter/recon/`, `integrations/tools/` | Asset discovery, scope-aware integrations, shared ToolRunner |
| `m_hunter/reporting/` | Report model, normalizer, JSON/Markdown/HTML renderers |
| `m_hunter/cli/` | Typer presentation layer |
| `m_hunter/gui/` | Optional PySide6 shell and headless controller |
| `m_hunter/ai/` | Optional provider-neutral analyst service and mock |
| `m_hunter/events/` | UI-neutral scan lifecycle/progress events |
| `tests/` | Unit, integration, security regression, and local E2E coverage |
| `docs/` | Architecture and security coverage status |

## Security and responsible use

Use M-Hunter only for systems you own or are explicitly authorized to test.
Configure scope narrowly. Active scanning can affect services; review the
selected modules and tools before enabling it. See [SECURITY.md](SECURITY.md)
for vulnerability reporting guidance.

## Roadmap

- Increase category-specific validation and end-to-end coverage, guided by the
  security coverage matrix.
- Improve durable scan-result storage and richer progress views.
- Add opt-in provider integrations only with explicit secret handling and
  analyst review.
- Expand the desktop UI without moving scan logic out of ApplicationService.
- Keep API/GUI clients, reports, and AI recommendations subordinate to the
  existing scope, validation, and Evidence boundaries.

## License

M-Hunter is distributed under the MIT License. See [LICENSE](LICENSE).
