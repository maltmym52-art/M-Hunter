from m_hunter.application.factory import create_default_application_service


def test_factory_separates_http_and_external_tool_timeouts():
    service = create_default_application_service(external_tools=True)

    assert service.http_engine.timeout == 10.0
    assert service.tool_runner.default_timeout == 45.0

    sources = service.recon_pipeline.discovery.get_sources()
    timeouts = {
        source.name: source.timeout
        for source in sources
        if source.name in {"subfinder", "amass"}
    }

    assert timeouts == {
        "subfinder": 45.0,
        "amass": 45.0,
    }


def test_factory_accepts_custom_external_tool_timeout():
    service = create_default_application_service(
        timeout=7.0,
        external_tool_timeout=45.0,
        external_tools=True,
    )

    assert service.http_engine.timeout == 7.0
    assert service.tool_runner.default_timeout == 45.0

    sources = service.recon_pipeline.discovery.get_sources()
    timeouts = {
        source.name: source.timeout
        for source in sources
        if source.name in {"subfinder", "amass"}
    }

    assert timeouts == {
        "subfinder": 45.0,
        "amass": 45.0,
    }


def test_factory_registers_runnable_http_response_security_analyzer():
    from m_hunter.application import ScanRequest
    from m_hunter.core.response import HttpResponse

    target = "http://127.0.0.1:8765/"
    body = b"Upstream service 10.20.30.40"
    service = create_default_application_service()
    assert "http_response_security" in service.analyzer_registry.names()

    result = service.run(ScanRequest(
        target,
        run_scanners=False,
        supplied_responses={target: HttpResponse(
            status_code=200,
            url=target,
            headers={"Server": "nginx/1.25.3"},
            content=body,
            cookies={},
            response_time=0.01,
            content_length=len(body),
        )},
    ))

    finding = next(item for item in result.findings
                   if item.title == "Server Version Disclosure")
    assert finding.evidence == "nginx/1.25.3"
    assert finding.evidence_ids
    assert any(
        item.title == "Internal IP Address Disclosure"
        and item.evidence == "10.20.30.40"
        for item in result.findings
    )
