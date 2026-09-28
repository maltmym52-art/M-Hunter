# Changelog

## [0.1.0] - 2026-09-29

Initial productization milestone for the modular M-Hunter security research
platform.

### Added

- Core scan, target, HTTP, lifecycle, and canonical `core.Finding` models.
- Unified `AnalysisContext` / `AnalysisResult` analyzer contracts with adapters
  and registry support for legacy analyzers.
- Validation-to-Finding conversion with existing indicator-validator adapters.
- Evidence capture with separate raw/sanitized data, redaction, and size bounds.
- ApplicationService orchestration for scope, authorization, Recon, HTTP,
  scanners, analyzers, validation, Evidence, Findings, and scan results.
- Typer/Rich CLI commands for scan, Recon, saved-response analysis, reporting,
  tools, help, and version.
- Versioned JSON, Markdown, and self-contained HTML reporting.
- Optional Recon integrations for Subfinder, Amass, httpx, Nmap, ffuf, and
  Nuclei through the shared ToolRunner; binaries remain optional.
- Security coverage matrix and local end-to-end tests for integrated passive
  headers, cookies, cache, context-based analysis, and legacy adapters.
- Optional PySide6 GUI shell/controller and transport-neutral scan events.
- Optional AI analyst contracts with sanitized immutable inputs and a local
  mock provider; AI output is advisory and cannot create Findings.

### Notes

- The release does not claim every analyzer category is integrated or
  production-ready. See `docs/security-coverage-matrix.md`.
- Active operations require explicit opt-in, authorization, and scope checks.
- No AI network provider, API key, or external scanning binary is required by
  the core package.
