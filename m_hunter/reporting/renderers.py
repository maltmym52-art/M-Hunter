"""Offline renderers for normalized report documents."""

from html import escape
import json
from typing import Protocol

from m_hunter.reporting.model import ReportModel
from m_hunter.reporting.normalize import to_json_value


class ReportRenderer(Protocol):
    """Renderer interface consumed by ReportService."""

    def render(self, report: ReportModel) -> str: ...


class JSONRenderer:
    """Render the versioned structured JSON report format."""

    def render(self, report: ReportModel) -> str:
        return json.dumps(to_json_value(report.to_dict()), ensure_ascii=False,
                          indent=2, sort_keys=True) + "\n"


class MarkdownRenderer:
    """Render a readable Markdown report for review and issue tracking."""

    def render(self, report: ReportModel) -> str:
        lines = [
            "# M-Hunter Security Report", "",
            f"- **Schema:** {report.schema} {report.schema_version}",
            f"- **Target:** {_md(report.target)}",
            f"- **Status:** {_md(report.status)}",
            f"- **Duration:** {report.duration_seconds:.2f} seconds",
            f"- **Started:** {_md(report.started_at or '—')}",
            f"- **Finished:** {_md(report.finished_at or '—')}",
            f"- **In scope:** {_md(report.scope.get('in_scope', 'unknown'))}",
            f"- **Active enabled:** {_md(report.authorization.get('active_enabled', False))}",
            f"- **Authorization granted:** {_md(report.authorization.get('granted', False))}",
            "", "## Summary", "",
            f"- Assets discovered: {len(report.assets)}",
            f"- Findings: {len(report.findings)}",
            f"- Evidence records: {report.statistics.get('evidence_records', 0)}",
            f"- Errors: {len(report.errors)}", "",
            "## Findings", "",
        ]
        if not report.findings:
            lines.append("No findings were reported.")
        for finding in report.findings:
            lines.extend([
                f"### {_md(finding.get('title', 'Untitled'))}", "",
                f"- **Severity:** {_md(finding.get('severity', 'unknown'))}",
                f"- **Confidence:** {_md(finding.get('confidence', 'unknown'))}",
                f"- **Status:** {_md(finding.get('status', 'unknown'))}",
                f"- **Endpoint:** {_md(finding.get('endpoint') or '—')}",
                f"- **Parameter:** {_md(finding.get('parameter') or '—')}",
                f"- **CWE:** {_md(finding.get('cwe') or '—')}",
                f"- **OWASP:** {_md(finding.get('owasp') or '—')}", "",
                _md(finding.get("description") or "No description provided."), "",
                "**Remediation**", "", _md(finding.get("remediation") or "No remediation provided."), "",
                "**Evidence**", "",
            ])
            if not finding.get("evidence"):
                lines.append("No evidence snapshot is attached.")
            for evidence in finding.get("evidence", []):
                lines.append(f"- Evidence ID: `{_md(evidence.get('id', ''))}`")
                if evidence.get("url"):
                    lines.append(f"- URL: {_md(evidence['url'])}")
                if evidence.get("method"):
                    lines.append(f"- Method: {_md(evidence['method'])}")
                if evidence.get("status_code") is not None:
                    lines.append(f"- HTTP status: {evidence['status_code']}")
                if evidence.get("parameter"):
                    lines.append(f"- Parameter: {_md(evidence['parameter'])}")
                if evidence.get("description"):
                    lines.append(f"- Context: {_md(evidence['description'])}")
                for name, value in evidence.get("headers", {}).items():
                    lines.append(f"- Header `{_md(name)}`: `{_md(value)}`")
                for label in ("request", "response"):
                    if evidence.get(label) is not None:
                        block = json.dumps(evidence[label], ensure_ascii=False, indent=2, sort_keys=True)
                        lines.extend(["", f"**HTTP {label}**", "", "```json", block.replace("```", "&#96;&#96;&#96;"), "```"])
                if evidence.get("evidence"):
                    lines.extend(["", "```text", str(evidence["evidence"]).replace("```", "&#96;&#96;&#96;"), "```"])
                if evidence.get("body"):
                    lines.extend(["", "```text", str(evidence["body"]).replace("```", "&#96;&#96;&#96;"), "```"])
                lines.append("")
        lines.extend(["## Statistics", "", "| Metric | Value |", "|---|---:|"])
        lines.extend(f"| {_md(key)} | {_md(value)} |" for key, value in sorted(report.statistics.items()))
        lines.extend(["", "## Errors", ""])
        if not report.errors:
            lines.append("No errors were recorded.")
        else:
            for issue in report.errors:
                lines.append(f"- **{_md(issue.get('level', 'error'))}** `{_md(issue.get('component', 'unknown'))}` at `{_md(issue.get('stage', 'unknown'))}`: {_md(issue.get('error', ''))}")
        return "\n".join(lines).rstrip() + "\n"


class HTMLRenderer:
    """Render a self-contained HTML report with inline styles and no CDN."""

    def render(self, report: ReportModel) -> str:
        findings = []
        for index, item in enumerate(report.findings, 1):
            evidence_html = []
            for evidence in item.get("evidence", []):
                details = [f"<p><strong>Evidence ID:</strong> { _h(evidence.get('id', '')) }</p>"]
                if evidence.get("url"):
                    details.append(f"<p><strong>URL:</strong> { _h(evidence['url']) }</p>")
                if evidence.get("status_code") is not None:
                    details.append(f"<p><strong>HTTP status:</strong> {evidence['status_code']}</p>")
                if evidence.get("method"):
                    details.append(f"<p><strong>Method:</strong> {_h(evidence['method'])}</p>")
                if evidence.get("parameter"):
                    details.append(f"<p><strong>Parameter:</strong> {_h(evidence['parameter'])}</p>")
                if evidence.get("description"):
                    details.append(f"<p><strong>Context:</strong> {_h(evidence['description'])}</p>")
                for name, value in evidence.get("headers", {}).items():
                    details.append(f"<p><strong>{_h(name)}:</strong> {_h(json.dumps(value, ensure_ascii=False, sort_keys=True))}</p>")
                for label in ("request", "response"):
                    if evidence.get(label) is not None:
                        block = json.dumps(evidence[label], ensure_ascii=False, indent=2, sort_keys=True)
                        details.append(f"<h4>HTTP {label.title()}</h4><pre>{_h(block)}</pre>")
                for label in ("evidence", "body"):
                    if evidence.get(label):
                        details.append(f"<h4>{label.title()}</h4><pre>{_h(evidence[label])}</pre>")
                evidence_html.append("<div class=\"evidence\">" + "".join(details) + "</div>")
            findings.append(
                f"<article id=\"finding-{index}\"><h3>{_h(item.get('title', 'Untitled'))}</h3>"
                f"<p><span class=\"badge\">{_h(item.get('severity', 'unknown'))}</span> "
                f"Confidence: {_h(item.get('confidence', 'unknown'))}</p>"
                f"<dl><dt>Endpoint</dt><dd>{_h(item.get('endpoint') or '—')}</dd>"
                f"<dt>Parameter</dt><dd>{_h(item.get('parameter') or '—')}</dd>"
                f"<dt>CWE / OWASP</dt><dd>{_h(item.get('cwe') or '—')} / {_h(item.get('owasp') or '—')}</dd></dl>"
                f"<p>{_h(item.get('description') or '')}</p><h4>Remediation</h4><p>{_h(item.get('remediation') or '—')}</p>"
                f"<h4>Evidence</h4>{''.join(evidence_html) or '<p>No evidence snapshot is attached.</p>'}</article>"
            )
        stats = "".join(f"<tr><th>{_h(key)}</th><td>{_h(value)}</td></tr>" for key, value in sorted(report.statistics.items()))
        errors = "".join(f"<li><strong>{_h(item.get('component', 'unknown'))}</strong> ({_h(item.get('stage', 'unknown'))}): {_h(item.get('error', ''))}</li>" for item in report.errors) or "<li>No errors were recorded.</li>"
        finding_nav = "".join(f"<li><a href=\"#finding-{i}\">{_h(item.get('title', 'Untitled'))}</a></li>" for i, item in enumerate(report.findings, 1)) or "<li>No findings</li>"
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>M-Hunter Security Report — {_h(report.target)}</title>
<style>
:root{{color-scheme:light;--ink:#182230;--muted:#5d6b7c;--line:#dce3eb;--accent:#1458a6;--panel:#f5f8fb}}
*{{box-sizing:border-box}}body{{margin:0;background:#edf2f7;color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
header,main{{max-width:1080px;margin:0 auto;padding:24px}}header{{background:#102b49;color:white;max-width:none;padding-left:max(24px,calc((100% - 1032px)/2))}}
header p{{color:#ccdae8}}nav,section,article{{background:white;border:1px solid var(--line);border-radius:10px;padding:20px;margin:16px 0}}
nav a{{color:var(--accent)}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
.card{{background:var(--panel);padding:14px;border-radius:8px}}.badge{{background:#e8eef7;padding:3px 9px;border-radius:20px;font-weight:700}}
dt{{font-weight:700;color:var(--muted)}}dd{{margin:0 0 8px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#101a26;color:#e9f1fa;padding:14px;border-radius:7px}}
table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;border-bottom:1px solid var(--line);padding:8px}}.evidence{{background:var(--panel);padding:12px;margin:10px 0;border-radius:7px}}
</style></head><body><header><h1>M-Hunter Security Report</h1><p>{_h(report.target)} · { _h(report.status) } · Schema { _h(report.schema_version) }</p></header>
<main><nav><strong>Report navigation</strong><ul><li><a href="#summary">Summary</a></li><li><a href="#findings">Findings</a><ul>{finding_nav}</ul></li><li><a href="#statistics">Statistics</a></li><li><a href="#errors">Errors</a></li></ul></nav>
<section id="summary"><h2>Summary</h2><div class="grid"><div class="card"><strong>Status</strong><br>{_h(report.status)}</div><div class="card"><strong>Assets</strong><br>{len(report.assets)}</div><div class="card"><strong>Findings</strong><br>{len(report.findings)}</div><div class="card"><strong>Duration</strong><br>{report.duration_seconds:.2f}s</div><div class="card"><strong>Started</strong><br>{_h(report.started_at or '—')}</div><div class="card"><strong>Finished</strong><br>{_h(report.finished_at or '—')}</div><div class="card"><strong>In scope</strong><br>{_h(report.scope.get('in_scope', 'unknown'))}</div><div class="card"><strong>Active enabled</strong><br>{_h(report.authorization.get('active_enabled', False))}</div><div class="card"><strong>Authorization granted</strong><br>{_h(report.authorization.get('granted', False))}</div></div></section>
<section id="findings"><h2>Findings</h2>{''.join(findings) or '<p>No findings were reported.</p>'}</section>
<section id="statistics"><h2>Statistics</h2><table>{stats}</table></section><section id="errors"><h2>Errors</h2><ul>{errors}</ul></section>
<footer><p>Generated by M-Hunter · report schema {_h(report.schema_version)}</p></footer></main></body></html>
"""


def _h(value: object) -> str:
    return escape(str(value), quote=True)


def _md(value: object) -> str:
    text = str(value)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
