from m_hunter.core.target import Target


def test_target_parsing():
    target = Target("https://example.com:8443/login")

    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port == 8443


def test_target_base_url_with_port():
    target = Target("https://example.com:8443/login")

    assert target.base_url == "https://example.com:8443"


def test_target_base_url_without_port():
    target = Target("https://example.com/login")

    assert target.base_url == "https://example.com"


def test_target_http_scheme():
    target = Target("http://example.com/test")

    assert target.scheme == "http"
    assert target.host == "example.com"
    assert target.port is None
    assert target.base_url == "http://example.com"


def test_target_root_url():
    target = Target("https://example.com")

    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port is None
    assert target.base_url == "https://example.com"


def test_target_with_query():
    target = Target("https://example.com/search?q=test")

    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port is None
    assert target.base_url == "https://example.com"


def test_target_with_path_and_query():
    target = Target("https://example.com/api/users?id=10")

    assert target.host == "example.com"
    assert target.base_url == "https://example.com"


def test_target_with_custom_http_port():
    target = Target("http://example.com:8080/api")

    assert target.scheme == "http"
    assert target.host == "example.com"
    assert target.port == 8080
    assert target.base_url == "http://example.com:8080"


def test_target_with_subdomain():
    target = Target("https://api.example.com/v1")

    assert target.host == "api.example.com"
    assert target.base_url == "https://api.example.com"


def test_target_preserves_original_url():
    url = "https://example.com/login?next=/dashboard"

    target = Target(url)

    assert target.url == url


def test_target_invalid_url_fallback():
    target = Target("example.com")

    assert target.scheme == ""
    assert target.host == ""
    assert target.port is None
    assert target.base_url == "example.com"
