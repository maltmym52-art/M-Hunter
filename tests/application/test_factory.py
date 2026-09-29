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
