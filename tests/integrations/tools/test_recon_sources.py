"""Contract and security tests for optional external Recon sources."""

import json
from pathlib import Path

import pytest

from m_hunter.application.models import AuthorizationGrant, ScanRequest, ScanState
from m_hunter.application.scope import ScopeViolation
from m_hunter.application.service import ApplicationService
from m_hunter.integrations.tools.catalog import ToolCatalog
from m_hunter.integrations.tools.recon_sources import (
    AmassSource,
    FfufSource,
    HttpxSource,
    NmapSource,
    NucleiSource,
)
from m_hunter.integrations.tools.runner import ToolResult
from m_hunter.integrations.tools.subfinder import SubfinderSource
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL


class FakeRunner:
    def __init__(self, outputs=None, *, installed=None, timed_out=False, return_code=0):
        self.outputs = outputs or {}
        self.installed = set(installed or self.outputs)
        self.timed_out = timed_out
        self.return_code = return_code
        self.calls = []

    def resolve(self, name):
        return f"/fake/bin/{name}" if name in self.installed else None

    def is_available(self, name):
        return name in self.installed

    def run(self, command, *, timeout=None, **kwargs):
        command = tuple(command)
        self.calls.append((command, timeout))
        name = Path(command[0]).name
        return ToolResult(command, self.return_code, self.outputs.get(name, ""), "", 0.01,
                          timed_out=self.timed_out)

    def run_if_available(self, executable, arguments=(), *, timeout=None, **kwargs):
        if not self.is_available(executable):
            return None
        return self.run([executable, *arguments], timeout=timeout, **kwargs)


def scope():
    return ScopeManager(URL("https://example.test/"))


@pytest.mark.parametrize("tool,source", [
    ("amass", AmassSource), ("httpx", HttpxSource), ("nmap", NmapSource),
    ("ffuf", FfufSource), ("nuclei", NucleiSource),
])
def test_tool_catalog_reports_missing_binary(tool, source):
    runner = FakeRunner(installed=set())
    status = ToolCatalog(runner).detect(tool)
    assert (status.installed, status.status, status.executable) == (False, "missing", None)
    instance = source(runner)
    if instance.capabilities.mode == "passive":
        assert instance.discover("https://example.test/") == []
    else:
        assert instance.discover_scoped("https://example.test/", scope_manager=scope(),
                                        authorization=AuthorizationGrant(True), active_enabled=True) == []
    assert instance.last_status == "missing"
    assert runner.calls == []


def test_tool_catalog_detects_path_and_sanitized_version():
    runner = FakeRunner({"httpx": "httpx v1.6.0\n"})
    status = ToolCatalog(runner).detect("httpx")
    assert status.status == "installed"
    assert status.executable == "/fake/bin/httpx"
    assert status.version == "httpx v1.6.0"


def test_amass_parses_and_deduplicates_passive_hostnames():
    runner = FakeRunner({"amass": "api.example.test\napi.example.test\nnot a host\n"})
    source = AmassSource(runner)
    assets = source.discover("example.test")
    assert [asset.value for asset in assets] == ["api.example.test"]
    assert assets[0].source == "amass"
    assert source.capabilities.mode == "passive"
    assert not source.capabilities.requires_authorization
    assert runner.calls[0][0][-3:] == ("-passive", "-d", "example.test")


def test_httpx_parses_http_observations_into_url_assets():
    runner = FakeRunner({"httpx": json.dumps({"url": "https://example.test/login", "status_code": 200, "title": "Login"}) + "\n"})
    source = HttpxSource(runner)
    assets = source.discover_scoped("https://example.test/", scope_manager=scope(),
                                    authorization=AuthorizationGrant(True), active_enabled=True)
    assert len(assets) == 1
    assert (assets[0].asset_type, assets[0].value) == ("url", "https://example.test/login")
    assert assets[0].metadata["status_code"] == "200"
    assert source.capabilities.mode == "active"
    assert source.capabilities.requires_authorization


def test_nmap_only_returns_bounded_open_web_port_observations():
    output = "Host: 203.0.113.10 (example.test)\tPorts: 80/open/tcp//http///, 22/open/tcp//ssh///\n"
    source = NmapSource(FakeRunner({"nmap": output}))
    assets = source.discover_scoped("https://example.test/", scope_manager=scope(),
                                    authorization=AuthorizationGrant(True), active_enabled=True)
    assert [(asset.value, asset.asset_type) for asset in assets] == [("http://example.test:80/", "endpoint")]
    assert "-p" in source.last_command
    assert source.last_command[source.last_command.index("-p") + 1] == "80,443,8000,8080,8443"


def test_ffuf_requires_existing_operator_wordlist_and_redacts_path(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FakeRunner({"ffuf": json.dumps({"results": [{"url": "https://example.test/admin", "status": 200, "length": 10}]})})
    source = FfufSource(runner, wordlist=wordlist)
    assets = source.discover_scoped("https://example.test/", scope_manager=scope(),
                                    authorization=AuthorizationGrant(True), active_enabled=True)
    assert assets[0].value == "https://example.test/admin"
    assert str(wordlist) not in json.dumps(source.last_command)
    assert "<WORDLIST>" in source.last_command


def test_ffuf_missing_wordlist_is_a_clear_configuration_error():
    source = FfufSource(FakeRunner({"ffuf": ""}), wordlist="missing-wordlist.txt")
    with pytest.raises(ValueError, match="existing --wordlist"):
        source.arguments("example.test", "https://example.test/")


def test_nuclei_output_remains_unvalidated_observation_not_finding():
    line = json.dumps({"matched-at": "https://example.test/item", "template-id": "test-id",
                       "info": {"severity": "high"}})
    source = NucleiSource(FakeRunner({"nuclei": line}))
    assets = source.discover_scoped("https://example.test/", scope_manager=scope(),
                                    authorization=AuthorizationGrant(True), active_enabled=True)
    assert len(assets) == 1
    assert assets[0].metadata["validation_state"] == "unvalidated_observation"
    assert assets[0].metadata["severity"] == "high"
    assert not hasattr(source, "findings")
    assert "-no-interactsh" in source.last_command


@pytest.mark.parametrize("kwargs,expected", [
    ({"active_enabled": False, "authorization": AuthorizationGrant(True)}, "active mode"),
    ({"active_enabled": True, "authorization": AuthorizationGrant(False)}, "authorization"),
])
def test_active_tools_reject_without_mode_or_authorization_before_execution(kwargs, expected):
    runner = FakeRunner({"nmap": ""})
    source = NmapSource(runner)
    with pytest.raises(ScopeViolation, match=expected):
        source.discover_scoped("https://example.test/", scope_manager=scope(), **kwargs)
    assert runner.calls == []


def test_active_tool_rejects_out_of_scope_target_before_execution():
    runner = FakeRunner({"nmap": ""})
    source = NmapSource(runner)
    with pytest.raises(ScopeViolation, match="outside scope"):
        source.discover_scoped("https://outside.test/", scope_manager=scope(),
                               authorization=AuthorizationGrant(True), active_enabled=True)
    assert runner.calls == []


def test_active_tool_rejects_out_of_scope_discoveries():
    runner = FakeRunner({"httpx": "\n".join([
        json.dumps({"url": "https://example.test/ok"}),
        json.dumps({"url": "https://outside.test/no"}),
    ])})
    source = HttpxSource(runner)
    assets = source.discover_scoped("https://example.test/", scope_manager=scope(),
                                    authorization=AuthorizationGrant(True), active_enabled=True)
    assert [asset.value for asset in assets] == ["https://example.test/ok"]


@pytest.mark.parametrize("runner,output,status", [
    (FakeRunner({"httpx": "",}, timed_out=True), None, "timeout"),
    (FakeRunner({"httpx": "",}, return_code=2), None, "failed"),
    (FakeRunner({"httpx": "not-json"}), None, "malformed"),
    (FakeRunner({"httpx": ""}), [], "empty"),
])
def test_httpx_timeout_nonzero_malformed_and_empty_are_explicit(runner, output, status):
    source = HttpxSource(runner)
    if status in {"timeout", "failed", "malformed"}:
        with pytest.raises(Exception):
            source.discover_scoped("https://example.test/", scope_manager=scope(),
                                   authorization=AuthorizationGrant(True), active_enabled=True)
    else:
        assert source.discover_scoped("https://example.test/", scope_manager=scope(),
                                      authorization=AuthorizationGrant(True), active_enabled=True) == output
    assert source.last_status == status
    assert runner.calls
    assert isinstance(runner.calls[0][0], tuple)


def test_active_source_cannot_be_called_through_legacy_passive_entrypoint():
    source = NmapSource(FakeRunner({"nmap": ""}))
    with pytest.raises(ScopeViolation):
        source.discover("https://example.test/")


def test_application_service_uses_injected_subfinder_and_filters_assets_by_scope():
    runner = FakeRunner({"subfinder": "api.example.test\noutside.test\n"})
    source = SubfinderSource(runner)
    authorized_scope = ScopeManager(URL("https://example.test/"),
                                   allowed_hosts={"example.test", "api.example.test"})
    service = ApplicationService(tool_runner=runner, recon_sources=[source], scope_manager=authorized_scope)
    result = service.run(ScanRequest("https://example.test/", recon=True,
                                     recon_source_names=("subfinder",),
                                     run_scanners=False, run_analyzers=False))
    assert result.state == ScanState.COMPLETED  # rejected discoveries are warnings, not scan failures
    assert {asset.value for asset in result.assets} == {"https://example.test/", "api.example.test"}
    assert any("out of scope" in issue.error for issue in result.issues)
    assert runner.calls


def test_passive_source_does_not_silently_perform_active_work():
    runner = FakeRunner({"amass": "api.example.test\n"})
    source = AmassSource(runner)
    source.discover("example.test")
    assert len(runner.calls) == 1
    assert "-passive" in runner.calls[0][0]
    assert "-u" not in runner.calls[0][0]
