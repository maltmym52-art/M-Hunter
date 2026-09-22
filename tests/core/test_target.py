from m_hunter.core.target import Target


def test_target_parsing():
    target = Target("https://example.com:8443/login")

    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port == 8443


def test_target_base_url_with_port():
    target = Target("https://example.com:8443/login")

    assert target.base_url == "https://example.com:8443"
