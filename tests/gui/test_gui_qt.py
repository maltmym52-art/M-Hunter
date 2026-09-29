"""Small, display-server-independent smoke test for the optional Qt shell."""

from __future__ import annotations

import pytest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from time import monotonic

from m_hunter.application.factory import create_default_application_service
from m_hunter.application.service import ApplicationService
from m_hunter.gui.app import launch


def test_main_window_is_constructed_and_shown_offscreen(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    qt_core = pytest.importorskip("PySide6.QtCore")
    qt_widgets = pytest.importorskip("PySide6.QtWidgets")

    app = qt_widgets.QApplication.instance() or qt_widgets.QApplication([])
    service = ApplicationService()
    service.tools_status = lambda **_kwargs: []
    observed = []

    def inspect_window():
        window = next(
            (item for item in app.topLevelWidgets()
             if isinstance(item, qt_widgets.QMainWindow) and item.isVisible()),
            None,
        )
        observed.append(window.windowTitle() if window is not None else None)
        if window is not None:
            observed.append(window.mode.currentText())
        if window is not None:
            window.close()
        app.quit()

    qt_core.QTimer.singleShot(50, inspect_window)
    try:
        assert launch(service, argv=[]) == 0
        assert observed == ["M-Hunter", "Passive"]
    finally:
        service.close()


def test_authorized_local_scan_renders_finding_evidence_and_asset(monkeypatch, tmp_path):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    qt_core = pytest.importorskip("PySide6.QtCore")
    qt_widgets = pytest.importorskip("PySide6.QtWidgets")
    report_path = tmp_path / "local-report.json"
    monkeypatch.setattr(
        qt_widgets.QFileDialog, "getSaveFileName",
        lambda *_args, **_kwargs: (str(report_path), "JSON"),
    )

    class LocalTarget(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"local authorized test response"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalTarget)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    app = qt_widgets.QApplication.instance() or qt_widgets.QApplication([])
    service = create_default_application_service(external_tools=False)
    service.tools_status = lambda **_kwargs: []
    observations = {}
    target_url = f"http://127.0.0.1:{server.server_port}/"

    def begin_scan():
        window = next(
            item for item in app.topLevelWidgets()
            if isinstance(item, qt_widgets.QMainWindow) and item.isVisible()
        )
        window.target.setText(target_url)
        window.mode.setCurrentText("Active")
        window.auth_ref.setText("local-fixture-authorization")
        window.start_button.click()
        deadline = monotonic() + 10

        def inspect_result():
            done = window.finding_table.rowCount() > 0 and window.evidence_list.rowCount() > 0
            if done or monotonic() >= deadline:
                observations["status"] = window.system_state.text()
                observations["findings"] = window.finding_table.rowCount()
                observations["evidence"] = window.evidence_list.rowCount()
                observations["assets"] = window.asset_table.rowCount()
                if observations["findings"]:
                    window.finding_table.selectRow(0)
                    observations["finding_detail"] = window.finding_details.toPlainText()
                if observations["evidence"]:
                    window.evidence_list.selectRow(0)
                    observations["evidence_detail"] = window.evidence_view.toPlainText()
                window.report_format.setCurrentText("json")
                window.report_button.click()

                def inspect_report():
                    if report_path.is_file() or monotonic() >= deadline:
                        observations["report"] = report_path.read_text(encoding="utf-8") if report_path.is_file() else ""
                        window.close()
                        app.quit()
                    else:
                        qt_core.QTimer.singleShot(50, inspect_report)

                qt_core.QTimer.singleShot(50, inspect_report)
            else:
                qt_core.QTimer.singleShot(50, inspect_result)

        qt_core.QTimer.singleShot(50, inspect_result)

    qt_core.QTimer.singleShot(50, begin_scan)
    try:
        assert launch(service, argv=[]) == 0
        assert observations["findings"] > 0
        assert observations["evidence"] > 0
        assert observations["assets"] > 0
        assert target_url in observations["finding_detail"]
        assert target_url.rstrip("/") in observations["evidence_detail"]
        assert "Missing Strict-Transport-Security Header" in observations["report"]
    finally:
        service.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


def test_active_mode_requires_authorization_reference_in_the_window(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    qt_core = pytest.importorskip("PySide6.QtCore")
    qt_widgets = pytest.importorskip("PySide6.QtWidgets")
    calls = []
    warnings = []
    monkeypatch.setattr(qt_widgets.QMessageBox, "warning", lambda *args: warnings.append(args[2]))

    app = qt_widgets.QApplication.instance() or qt_widgets.QApplication([])
    service = ApplicationService()
    service.tools_status = lambda **_kwargs: []
    service.run = lambda request: calls.append(request)

    def try_active_scan():
        window = next(
            item for item in app.topLevelWidgets()
            if isinstance(item, qt_widgets.QMainWindow) and item.isVisible()
        )
        window.target.setText("https://authorized.example.test/")
        window.mode.setCurrentText("Active")
        window.start_button.click()
        window.close()
        app.quit()

    qt_core.QTimer.singleShot(50, try_active_scan)
    try:
        assert launch(service, argv=[]) == 0
        assert calls == []
        assert warnings and "authorization reference" in warnings[0].lower()
    finally:
        service.close()
