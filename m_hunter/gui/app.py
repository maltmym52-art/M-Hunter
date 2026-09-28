"""Optional PySide6 desktop shell; install with the ``gui`` extra."""

from __future__ import annotations

import sys
from typing import Any

from m_hunter.ai.service import AIAnalysisService
from m_hunter.application.models import AuthorizationGrant, ScanRequest
from m_hunter.application.factory import create_default_application_service
from m_hunter.application.service import ApplicationService
from m_hunter.gui.controller import GUIController


class GUIUnavailableError(RuntimeError):
    """Raised with installation guidance when optional Qt is unavailable."""


def launch(application_service: ApplicationService, argv: list[str] | None = None,
           ai_analysis_service: AIAnalysisService | None = None) -> int:
    """Launch the optional UI; importing the package itself never requires Qt."""
    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import (
            QApplication, QCheckBox, QFormLayout, QLineEdit, QMainWindow,
            QMessageBox, QPushButton, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
        )
    except ImportError as exc:
        raise GUIUnavailableError("Desktop UI requires optional dependency; install m-hunter[gui].") from exc

    controller = GUIController(application_service, ai_analysis_service=ai_analysis_service)
    app = QApplication(argv or [])

    class HunterWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("M-Hunter")
            self.resize(1000, 700)
            self.tabs = QTabWidget()
            self.setCentralWidget(self.tabs)
            self.pages: dict[str, QTextEdit] = {}
            for name in controller.PAGES:
                if name == "New Scan":
                    self.tabs.addTab(self._new_scan_page(), name)
                elif name == "AI Analyst":
                    self.tabs.addTab(self._ai_page(), name)
                else:
                    view = QTextEdit()
                    view.setReadOnly(True)
                    view.setPlainText(self._page_content(name))
                    self.pages[name] = view
                    self.tabs.addTab(view, name)
            self.timer = QTimer(self)
            self.timer.timeout.connect(self._refresh)
            self.timer.start(400)

        def _new_scan_page(self) -> QWidget:
            page = QWidget()
            form = QFormLayout(page)
            self.target = QLineEdit()
            self.target.setPlaceholderText("https://authorized.example")
            self.active = QCheckBox("Enable active testing")
            self.authorization = QLineEdit()
            self.authorization.setPlaceholderText("Authorization reference (required for active)")
            self.recon = QCheckBox("Run configured passive Recon")
            self.status = QTextEdit()
            self.status.setReadOnly(True)
            start = QPushButton("Start scan")
            cancel = QPushButton("Request cancellation")
            start.clicked.connect(self._start)
            cancel.clicked.connect(lambda: controller.cancel_scan())
            form.addRow("Target", self.target)
            form.addRow("Mode", self.active)
            form.addRow("Authorization", self.authorization)
            form.addRow("Recon", self.recon)
            form.addRow(start, cancel)
            form.addRow("Progress", self.status)
            return page

        def _ai_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            view = QTextEdit()
            view.setReadOnly(True)
            self.pages["AI Analyst"] = view
            analyze = QPushButton("Analyze last scan (advisory only)")
            analyze.clicked.connect(self._analyze)
            layout.addWidget(analyze)
            layout.addWidget(view)
            return page

        def _analyze(self) -> None:
            try:
                controller.analyze_last_scan()
                self._refresh()
            except RuntimeError as exc:
                QMessageBox.information(self, "AI Analyst", str(exc))

        def _start(self) -> None:
            target = self.target.text().strip()
            active = self.active.isChecked()
            reference = self.authorization.text().strip() or None
            if active and not reference:
                QMessageBox.warning(self, "Authorization required", "Active testing needs an authorization reference.")
                return
            try:
                future = controller.start_scan(ScanRequest(
                    target=target,
                    active=active,
                    authorization=AuthorizationGrant(active, reference if active else None),
                    recon=self.recon.isChecked(),
                ))
                future.add_done_callback(lambda _done: QTimer.singleShot(0, self._refresh))
            except (TypeError, ValueError, RuntimeError) as exc:
                QMessageBox.warning(self, "Scan could not start", str(exc))

        def _refresh(self) -> None:
            data = controller.view_data()
            self.status.setPlainText(self._format(data))
            for name, view in self.pages.items():
                view.setPlainText(self._page_content(name, data))

        def _format(self, data: dict[str, Any]) -> str:
            progress = data.get("progress")
            if data["scan"] is None:
                if progress:
                    return (f"Stage: {progress['stage']} ({(progress['progress'] or 0):.0%})\n"
                            f"Target: {progress['target']}\n"
                            f"Assets: {progress['discovered_assets']}  Findings: {progress['findings_count']}  "
                            f"Errors: {progress['errors_count']}\n")
                return "Ready. Scanning is performed by ApplicationService."
            return (f"Status: {data['scan']['status']}\nTarget: {data['target']}\n"
                    f"Assets: {len(data['assets'])}\nFindings: {len(data['findings'])}\n"
                    f"Errors: {len(data['errors'])}\n")

        def _page_content(self, name: str, data: dict[str, Any] | None = None) -> str:
            if not data or data["scan"] is None:
                return f"{name}\n\nScan and security operations are provided by the shared ApplicationService."
            mapping = {
                "Dashboard": data["scan"], "Targets": data["target"], "Scope": data["scope"],
                "Recon": data["assets"], "Scan Progress": data["scan"],
                "Findings": data["findings"], "Finding Details": data["findings"],
                "Evidence": data["evidence"], "Reports": "Use the shared report renderer.",
                "AI Analyst": data.get("ai_analysis") or "AI provider is optional and not configured.",
                "Tools Status": data["tools"],
                "Settings": "Presentation settings only; scanning policy is owned by ApplicationService.",
            }
            return f"{name}\n\n{mapping.get(name, '')}"

        def closeEvent(self, event) -> None:  # noqa: N802 - Qt callback contract
            controller.close()
            application_service.close()
            event.accept()

    window = HunterWindow()
    window.show()
    return app.exec()


def main() -> int:
    """Standalone entry point using the same application service contract as CLI."""
    service = create_default_application_service(external_tools=False)
    try:
        return launch(service)
    except GUIUnavailableError as exc:
        service.close()
        print(str(exc), file=sys.stderr)
        return 2
