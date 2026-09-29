"""Optional PySide6 desktop presentation for the shared application service."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from m_hunter.ai.service import AIAnalysisService
from m_hunter.application.factory import create_default_application_service
from m_hunter.application.models import AuthorizationGrant, ScanRequest
from m_hunter.application.service import ApplicationService
from m_hunter.gui.controller import GUIController

GUI_RECON_SOURCES = ("subfinder", "amass", "httpx", "nmap", "ffuf", "nuclei")


class GUIUnavailableError(RuntimeError):
    """Raised with installation guidance when optional Qt is unavailable."""


def launch(application_service: ApplicationService, argv: list[str] | None = None,
           ai_analysis_service: AIAnalysisService | None = None) -> int:
    """Launch the Qt UI; the controller delegates all work to app services."""
    try:
        from PySide6.QtCore import Qt, QTimer
        from PySide6.QtWidgets import (
            QApplication, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog,
            QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
            QMessageBox, QProgressBar, QPushButton, QSpinBox, QTabWidget,
            QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
        )
    except ImportError as exc:
        raise GUIUnavailableError("Desktop UI requires optional dependency; install m-hunter[gui].") from exc

    controller = GUIController(application_service, ai_analysis_service=ai_analysis_service)
    app = QApplication.instance() or QApplication(argv or [])

    class HunterWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("M-Hunter")
            self.resize(1280, 850)
            self.setStyleSheet("""
                QMainWindow, QWidget { background: #101820; color: #e6edf3; }
                QGroupBox { border: 1px solid #344454; border-radius: 8px; margin-top: 10px; padding: 10px; font-weight: 600; }
                QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 5px; }
                QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QTextEdit, QTableWidget { background: #17232e; border: 1px solid #344454; border-radius: 5px; padding: 5px; }
                QPushButton { background: #167d9a; border: 0; border-radius: 5px; padding: 8px 14px; font-weight: 600; }
                QPushButton:hover { background: #2297b6; }
                QHeaderView::section { background: #20313f; padding: 6px; border: 0; }
                QTabBar::tab { background: #17232e; padding: 9px 16px; }
                QTabBar::tab:selected { background: #167d9a; }
            """)
            root = QWidget()
            outer = QVBoxLayout(root)
            header = QHBoxLayout()
            title = QLabel("M-Hunter")
            title.setStyleSheet("font-size: 25px; font-weight: 700; color: #64d2e8")
            self.system_state = QLabel("Ready · v0.1.0")
            header.addWidget(title)
            header.addStretch()
            header.addWidget(self.system_state)
            outer.addLayout(header)
            self.tabs = QTabWidget()
            self.setCentralWidget(root)
            outer.addWidget(self.tabs)
            self._build_scan_tab()
            self._build_findings_tab()
            self._build_assets_tab()
            self._build_evidence_tab()
            self._build_tools_tab()
            self._build_reports_tab()
            self._build_ai_tab()
            self._report_future = None
            self._ai_future = None
            self._report_save_path = None
            self._shown_issues: set[str] = set()
            self.timer = QTimer(self)
            self.timer.timeout.connect(self._refresh)
            self.timer.start(350)
            self._refresh()

        def _build_scan_tab(self) -> None:
            page = QWidget()
            layout = QVBoxLayout(page)
            target_group = QGroupBox("Target & authorization")
            form = QFormLayout(target_group)
            self.target = QLineEdit()
            self.target.setPlaceholderText("https://authorized.example")
            self.mode = QComboBox()
            self.mode.addItems(["Passive", "Active"])
            self.auth_ref = QLineEdit()
            self.auth_ref.setPlaceholderText("Authorization reference required for Active")
            self.auth_ref.setEnabled(False)
            self.mode.currentTextChanged.connect(lambda value: self.auth_ref.setEnabled(value == "Active"))
            form.addRow("Target URL", self.target)
            form.addRow("Mode", self.mode)
            form.addRow("Authorization reference", self.auth_ref)
            layout.addWidget(target_group)

            controls = QHBoxLayout()
            recon_box = QGroupBox("Recon")
            recon_layout = QVBoxLayout(recon_box)
            self.recon_enabled = QCheckBox("Enable Recon")
            self.external_enabled = QCheckBox("Enable external tools")
            recon_layout.addWidget(self.recon_enabled)
            recon_layout.addWidget(self.external_enabled)
            self.source_checks: dict[str, Any] = {}
            row = QHBoxLayout()
            for name in ("subfinder", "amass", "httpx", "nmap", "ffuf", "nuclei"):
                check = QCheckBox(name)
                check.setChecked(False)
                self.source_checks[name] = check
                row.addWidget(check)
            recon_layout.addLayout(row)
            wordlist_row = QHBoxLayout()
            self.wordlist = QLineEdit()
            self.wordlist.setPlaceholderText("Wordlist file (required only for ffuf)")
            choose_wordlist = QPushButton("Browse…")
            choose_wordlist.clicked.connect(self._choose_wordlist)
            wordlist_row.addWidget(self.wordlist)
            wordlist_row.addWidget(choose_wordlist)
            recon_layout.addLayout(wordlist_row)
            controls.addWidget(recon_box, 2)

            component_box = QGroupBox("Analysis components")
            component_form = QFormLayout(component_box)
            self.analyzers = self._registry_checks(application_service.analyzer_registry.names())
            self.scanners = self._registry_checks(application_service.scanner_registry.names())
            component_form.addRow("Analyzers", self.analyzers)
            component_form.addRow("Scanners", self.scanners)
            controls.addWidget(component_box, 1)
            layout.addLayout(controls)

            timing = QHBoxLayout()
            http_value = getattr(application_service.http_engine, "timeout", None)
            external_value = getattr(application_service.tool_runner, "default_timeout", None)
            http_text = f"HTTP timeout: {http_value:g} s" if http_value is not None else "HTTP timeout: service default"
            external_text = (f"External tool timeout: {external_value:g} s (default)"
                             if external_value is not None else "External tool timeout: source configured")
            http_label = QLabel(http_text)
            self.external_timeout = QLabel(external_text)
            timing.addWidget(http_label)
            timing.addWidget(self.external_timeout)
            timing.addStretch()
            layout.addLayout(timing)
            actions = QHBoxLayout()
            self.start_button = QPushButton("Start Scan")
            self.cancel_button = QPushButton("Stop / Cancel")
            self.cancel_button.setEnabled(False)
            self.start_button.clicked.connect(self._start)
            self.cancel_button.clicked.connect(self._cancel)
            actions.addWidget(self.start_button)
            actions.addWidget(self.cancel_button)
            actions.addStretch()
            layout.addLayout(actions)

            status_group = QGroupBox("Scan progress")
            status_layout = QVBoxLayout(status_group)
            self.stage_label = QLabel("Ready")
            self.progress_bar = QProgressBar()
            self.log = QTextEdit()
            self.log.setReadOnly(True)
            self.log.setMaximumHeight(150)
            self.counts = QLabel("Assets: 0 · Findings: 0 · Evidence: 0")
            status_layout.addWidget(self.stage_label)
            status_layout.addWidget(self.progress_bar)
            status_layout.addWidget(self.counts)
            status_layout.addWidget(self.log)
            layout.addWidget(status_group)
            self.tabs.addTab(page, "Scan")

        def _registry_checks(self, names: list[str]):
            widget = QWidget()
            box = QVBoxLayout(widget)
            box.setContentsMargins(0, 0, 0, 0)
            for name in names:
                check = QCheckBox(name)
                check.setChecked(True)
                box.addWidget(check)
            box.addStretch()
            return widget

        def _selected(self, widget) -> tuple[str, ...]:
            return tuple(child.text() for child in widget.findChildren(QCheckBox) if child.isChecked())

        def _choose_wordlist(self) -> None:
            path, _ = QFileDialog.getOpenFileName(self, "Choose ffuf wordlist")
            if path:
                self.wordlist.setText(path)

        def _table_tab(self, name: str, headers: list[str]):
            page = QWidget()
            layout = QVBoxLayout(page)
            filters = QHBoxLayout()
            search = QLineEdit()
            search.setPlaceholderText("Search")
            severity = QComboBox()
            severity.addItems(["All severities", "Critical", "High", "Medium", "Low", "Info"])
            confidence = QComboBox()
            confidence.addItems(["All confidence", "High", "Medium", "Low"])
            filters.addWidget(search)
            filters.addWidget(severity)
            filters.addWidget(confidence)
            layout.addLayout(filters)
            table = QTableWidget(0, len(headers))
            table.setHorizontalHeaderLabels(headers)
            table.setSortingEnabled(True)
            table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            table.horizontalHeader().setStretchLastSection(True)
            layout.addWidget(table)
            self.tabs.addTab(page, name)
            return table, search, severity, confidence

        def _build_findings_tab(self) -> None:
            self.finding_table, self.finding_search, self.severity_filter, self.confidence_filter = self._table_tab(
                "Findings", ["Severity", "Confidence", "Finding", "Endpoint", "Evidence"])
            self.finding_details = QTextEdit()
            self.finding_details.setReadOnly(True)
            self.finding_details.setMaximumHeight(210)
            self.tabs.widget(self.tabs.count() - 1).layout().addWidget(self.finding_details)
            self.finding_table.itemSelectionChanged.connect(self._show_finding)
            for widget in (self.finding_search, self.severity_filter, self.confidence_filter):
                if isinstance(widget, QLineEdit):
                    widget.textChanged.connect(self._filter_findings)
                else:
                    widget.currentTextChanged.connect(self._filter_findings)

        def _build_assets_tab(self) -> None:
            self.asset_table, _, _, _ = self._table_tab("Assets", ["URL", "Type", "Source", "Scope status"])

        def _build_evidence_tab(self) -> None:
            page = QWidget()
            layout = QVBoxLayout(page)
            self.evidence_list, _, _, _ = self._table_tab("Evidence", ["ID", "Finding", "URL", "Method", "Status"])
            self.evidence_view = QTextEdit()
            self.evidence_view.setReadOnly(True)
            self.evidence_view.setMaximumHeight(240)
            self.tabs.widget(self.tabs.count() - 1).layout().addWidget(self.evidence_view)
            self.evidence_list.itemSelectionChanged.connect(self._show_evidence)

        def _build_tools_tab(self) -> None:
            self.tool_table, _, _, _ = self._table_tab("Tools", ["Tool", "Status", "Executable", "Version"])

        def _build_reports_tab(self) -> None:
            page = QWidget()
            layout = QVBoxLayout(page)
            row = QHBoxLayout()
            self.report_format = QComboBox()
            self.report_format.addItems(["json", "markdown", "html"])
            self.report_button = QPushButton("Export report…")
            self.report_button.clicked.connect(self._export_report)
            row.addWidget(self.report_format)
            row.addWidget(self.report_button)
            row.addStretch()
            layout.addLayout(row)
            self.report_preview = QTextEdit()
            self.report_preview.setReadOnly(True)
            layout.addWidget(self.report_preview)
            self.tabs.addTab(page, "Reports")

        def _build_ai_tab(self) -> None:
            page = QWidget()
            layout = QVBoxLayout(page)
            self.ai_status = QLabel("Optional advisory analysis; no finding is created by AI.")
            button = QPushButton("Analyze current results")
            button.clicked.connect(self._analyze)
            self.ai_view = QTextEdit()
            self.ai_view.setReadOnly(True)
            layout.addWidget(self.ai_status)
            layout.addWidget(button)
            layout.addWidget(self.ai_view)
            self.tabs.addTab(page, "AI Analysis")

        def _start(self) -> None:
            target = self.target.text().strip()
            try:
                # ScanRequest/Target/ApplicationService remain authoritative for URL and scope validation.
                active = self.mode.currentText() == "Active"
                reference = self.auth_ref.text().strip() or None
                if active and not reference:
                    raise ValueError("Active scans require an authorization reference.")
                selected_sources = tuple(name for name, box in self.source_checks.items() if box.isChecked())
                wordlist = self.wordlist.text().strip() or None
                if "ffuf" in selected_sources and (wordlist is None or not Path(wordlist).is_file()):
                    raise ValueError("ffuf requires an existing wordlist file.")
                request = ScanRequest(
                    target=target, active=active,
                    authorization=AuthorizationGrant(active, reference if active else None),
                    recon=self.recon_enabled.isChecked(),
                    recon_source_names=selected_sources if self.external_enabled.isChecked() else (),
                    recon_wordlist=wordlist,
                    analyzer_names=self._selected(self.analyzers),
                    scanner_names=self._selected(self.scanners),
                    run_analyzers=bool(self._selected(self.analyzers)),
                    run_scanners=bool(self._selected(self.scanners)),
                )
                if selected_sources and not self.recon_enabled.isChecked():
                    raise ValueError("Enable Recon to run selected Recon sources.")
                if selected_sources and not self.external_enabled.isChecked():
                    raise ValueError("Enable external tools to run selected Recon sources.")
                controller.start_scan(request)
                self.start_button.setEnabled(False)
                self.cancel_button.setEnabled(True)
                self.stage_label.setText("Starting…")
                self.log.append("Scan submitted to ApplicationService.")
            except (TypeError, ValueError, RuntimeError) as exc:
                QMessageBox.warning(self, "Scan could not start", str(exc))

        def _cancel(self) -> None:
            if controller.cancel_scan():
                self.log.append("Cooperative cancellation requested.")

        def _refresh(self) -> None:
            data = controller.view_data(non_blocking_tools=True)
            running = controller.scan_running
            self.start_button.setEnabled(not running)
            self.cancel_button.setEnabled(running)
            progress = data.get("progress")
            if progress:
                self.stage_label.setText(f"{progress['stage']} · {progress['message'] or 'In progress'}")
                self.progress_bar.setValue(round((progress["progress"] or 0) * 100))
                self.counts.setText(f"Assets: {progress['discovered_assets']} · Findings: {progress['findings_count']} · Evidence: {len(data.get('evidence', ())) }")
            if data.get("scan"):
                self.system_state.setText(f"{data['scan']['status']} · v0.1.0")
                self._render_data(data)
            self._render_tools(data.get("tools", ()))
            if self._report_future is not None and self._report_future.done():
                try:
                    content = self._report_future.result()
                    self.report_preview.setPlainText(content)
                    if self._report_save_path:
                        Path(self._report_save_path).write_text(content, encoding="utf-8")
                        self._report_save_path = None
                        QMessageBox.information(self, "Report", "Report saved.")
                except Exception as exc:
                    QMessageBox.warning(self, "Report error", str(exc))
                self._report_future = None
            if self._ai_future is not None and self._ai_future.done():
                try:
                    self._ai_future.result()
                    self._render_ai(controller.view_data(non_blocking_tools=True).get("ai_analysis"))
                except Exception as exc:
                    self.ai_view.setPlainText(f"AI analysis failed: {exc}")
                self._ai_future = None

        def _render_data(self, data: dict[str, Any]) -> None:
            for issue in data.get("errors", ()):
                line = (f"{issue.get('level', 'error')}: {issue.get('component', 'scan')} "
                        f"({issue.get('stage', 'unknown')}): {issue.get('error', '')}")
                if line not in self._shown_issues:
                    self.log.append(line)
                    self._shown_issues.add(line)
            self.finding_table.setSortingEnabled(False)
            self.finding_table.setRowCount(0)
            for finding in data.get("findings", ()):
                row = self.finding_table.rowCount()
                self.finding_table.insertRow(row)
                values = [finding.get("severity", ""), finding.get("confidence", ""), finding.get("title", ""), finding.get("endpoint") or "—", str(len(finding.get("evidence", ())))]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    item.setData(Qt.ItemDataRole.UserRole, finding)
                    self.finding_table.setItem(row, col, item)
            self.finding_table.setSortingEnabled(True)
            self._filter_findings()
            self.asset_table.setRowCount(0)
            for asset in data.get("assets", ()):
                row = self.asset_table.rowCount()
                self.asset_table.insertRow(row)
                vals = [asset.get("value", ""), asset.get("type", ""), asset.get("source", ""), "Not supplied by backend"]
                for col, value in enumerate(vals): self.asset_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.evidence_list.setRowCount(0)
            for record in data.get("evidence", ()):
                row = self.evidence_list.rowCount()
                self.evidence_list.insertRow(row)
                vals = [record.get("id", ""), record.get("finding_id", ""), record.get("url", ""), record.get("method", ""), str(record.get("status_code", "—"))]
                for col, value in enumerate(vals):
                    item = QTableWidgetItem(str(value)); item.setData(Qt.ItemDataRole.UserRole, record)
                    self.evidence_list.setItem(row, col, item)
            if data.get("ai_analysis"):
                self._render_ai(data["ai_analysis"])

        def _render_ai(self, analysis) -> None:
            if not analysis:
                self.ai_view.clear()
                return
            lines = [f"Status: {analysis.get('status', 'unknown')}"]
            if analysis.get("error"):
                lines.append(f"Note: {analysis['error']}")
            for note in analysis.get("notes", ()):
                lines.extend([f"\n{note.get('kind', 'Analyst note')}", note.get("text", "")])
            self.ai_view.setPlainText("\n".join(lines))

        def _filter_findings(self, *_args) -> None:
            query = self.finding_search.text().casefold()
            severity = self.severity_filter.currentText()
            confidence = self.confidence_filter.currentText()
            for row in range(self.finding_table.rowCount()):
                vals = [self.finding_table.item(row, col).text() for col in range(4)]
                show = (not query or query in " ".join(vals).casefold())
                show &= severity == "All severities" or vals[0].casefold() == severity.casefold()
                show &= confidence == "All confidence" or vals[1].casefold() == confidence.casefold()
                self.finding_table.setRowHidden(row, not show)

        def _show_finding(self) -> None:
            selected = self.finding_table.selectedItems()
            if not selected: return
            finding = selected[0].data(Qt.ItemDataRole.UserRole)
            if finding:
                import json
                self.finding_details.setPlainText(json.dumps(finding, ensure_ascii=False, indent=2))

        def _show_evidence(self) -> None:
            selected = self.evidence_list.selectedItems()
            if selected:
                import json
                self.evidence_view.setPlainText(json.dumps(selected[0].data(Qt.ItemDataRole.UserRole), ensure_ascii=False, indent=2))

        def _render_tools(self, tools) -> None:
            self.tool_table.setRowCount(0)
            for tool in tools:
                row = self.tool_table.rowCount(); self.tool_table.insertRow(row)
                for col, value in enumerate((tool.get("name", ""), tool.get("status", "unknown"), tool.get("executable") or "—", tool.get("version") or "—")):
                    self.tool_table.setItem(row, col, QTableWidgetItem(str(value)))

        def _export_report(self) -> None:
            try:
                future = controller.start_report(self.report_format.currentText())
            except RuntimeError as exc:
                QMessageBox.information(self, "Report", str(exc)); return
            suffix = {"json": ".json", "markdown": ".md", "html": ".html"}[self.report_format.currentText()]
            path, _ = QFileDialog.getSaveFileName(self, "Save M-Hunter report", "report" + suffix)
            if path:
                self._report_future = future
                self._report_save_path = path
            else:
                self._report_future = future

        def _analyze(self) -> None:
            try:
                self._ai_future = controller.start_ai_analysis()
                self.ai_status.setText("Analysis running…")
            except RuntimeError as exc:
                QMessageBox.information(self, "AI Analysis", str(exc))

        def closeEvent(self, event) -> None:  # noqa: N802
            controller.close()
            application_service.close()
            event.accept()

    window = HunterWindow()
    window.show()
    return app.exec()


def main() -> int:
    """Standalone entry point using the standard ApplicationService factory."""
    service = create_default_application_service(
        external_tools=True, recon_source_names=GUI_RECON_SOURCES,
    )
    try:
        return launch(service)
    except GUIUnavailableError as exc:
        service.close()
        print(str(exc), file=sys.stderr)
        return 2
