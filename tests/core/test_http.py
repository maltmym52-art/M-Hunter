import pytest

from m_hunter.config.settings import HttpSettings
from m_hunter.core.http import HttpEngine


class FakeResponse:
    def __init__(
        self,
        status_code=200,
        url="https://example.com/final",
        headers=None,
        content=b"OK",
        cookies=None,
    ):
        self.status_code = status_code
        self.url = url
        self.headers = headers or {
            "content-type": "text/plain",
        }
        self.content = content
        self.cookies = cookies or {}


class FakeClient:
    last_instance = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.request_calls = []

        FakeClient.last_instance = self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def request(self, method, url, **kwargs):
        self.request_calls.append(
            {
                "method": method,
                "url": url,
                "kwargs": kwargs,
            }
        )

        return FakeResponse()


def create_engine(monkeypatch, **client_kwargs):
    def fake_client(**kwargs):
        FakeClient(**kwargs)

        instance = FakeClient.last_instance

        for key, value in client_kwargs.items():
            instance.kwargs[key] = value

        return instance

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        fake_client,
    )

    return HttpEngine()


def test_http_engine_defaults():
    engine = HttpEngine()

    assert engine.timeout == 10.0
    assert engine.follow_redirects is True
    assert engine.user_agent == "M-Hunter/0.1.0"


def test_http_engine_accepts_custom_settings():
    settings = HttpSettings(
        timeout=30.0,
        follow_redirects=False,
        user_agent="Custom-Agent/1.0",
    )

    engine = HttpEngine(settings)

    assert engine.settings is settings
    assert engine.timeout == 30.0
    assert engine.follow_redirects is False
    assert engine.user_agent == "Custom-Agent/1.0"


def test_http_engine_uses_settings_for_client(monkeypatch):
    settings = HttpSettings(
        timeout=25.0,
        follow_redirects=False,
        user_agent="Test-Agent/2.0",
    )

    captured = {}

    class Client:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine(settings)

    engine.get("https://example.com")

    assert captured["timeout"] == 25.0
    assert captured["follow_redirects"] is False
    assert captured["headers"] == {
        "User-Agent": "Test-Agent/2.0",
    }


def test_http_engine_creates_response(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    response = engine.get(
        "https://example.com/test"
    )

    assert response.status_code == 200
    assert response.url == "https://example.com/final"
    assert response.content == b"OK"
    assert response.content_length == 2
    assert response.get_content_type() == "text/plain"


def test_http_engine_passes_request_headers(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            self.request_kwargs = None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            self.request_kwargs = kwargs
            test_http_engine_passes_request_headers.request_kwargs = kwargs
            return FakeResponse()

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    engine.get(
        "https://example.com",
        headers={
            "Authorization": "Bearer test",
        },
    )

    assert (
        test_http_engine_passes_request_headers.request_kwargs[
            "headers"
        ]
        == {
            "Authorization": "Bearer test",
        }
    )


def test_http_engine_passes_cookies(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            test_http_engine_passes_cookies.request_kwargs = kwargs
            return FakeResponse()

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    engine.get(
        "https://example.com",
        cookies={
            "session": "abc",
        },
    )

    assert (
        test_http_engine_passes_cookies.request_kwargs[
            "cookies"
        ]
        == {
            "session": "abc",
        }
    )


def test_http_engine_passes_params(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            test_http_engine_passes_params.request_kwargs = kwargs
            return FakeResponse()

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    engine.get(
        "https://example.com",
        params={
            "page": "1",
        },
    )

    assert (
        test_http_engine_passes_params.request_kwargs[
            "params"
        ]
        == {
            "page": "1",
        }
    )


def test_http_engine_passes_data(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            test_http_engine_passes_data.request_kwargs = kwargs
            return FakeResponse()

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    engine.post(
        "https://example.com",
        data={
            "username": "test",
        },
    )

    assert (
        test_http_engine_passes_data.request_kwargs[
            "data"
        ]
        == {
            "username": "test",
        }
    )


def test_http_engine_passes_json(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            test_http_engine_passes_json.request_kwargs = kwargs
            return FakeResponse()

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    engine.post(
        "https://example.com",
        json={
            "username": "test",
        },
    )

    assert (
        test_http_engine_passes_json.request_kwargs[
            "json"
        ]
        == {
            "username": "test",
        }
    )


@pytest.mark.parametrize(
    "method",
    [
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
    ],
)
def test_http_methods(monkeypatch, method):
    calls = []

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method_name, url, **kwargs):
            calls.append(method_name)
            return FakeResponse()

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    getattr(engine, method)(
        "https://example.com"
    )

    assert calls == [method.upper()]


def test_http_engine_handles_timeout(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            import httpx

            raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    with pytest.raises(
        RuntimeError,
        match="HTTP request timed out",
    ):
        engine.get("https://example.com")


def test_http_engine_handles_connect_error(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            import httpx

            raise httpx.ConnectError("connection failed")

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    with pytest.raises(
        RuntimeError,
        match="Failed to connect",
    ):
        engine.get("https://example.com")


def test_http_engine_handles_network_error(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            import httpx

            raise httpx.NetworkError("network failed")

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    with pytest.raises(
        RuntimeError,
        match="Network error",
    ):
        engine.get("https://example.com")


def test_http_engine_handles_http_error(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            import httpx

            raise httpx.HTTPError("http failed")

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    with pytest.raises(
        RuntimeError,
        match="HTTP error",
    ):
        engine.get("https://example.com")


def test_http_engine_response_timing(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    response = engine.get(
        "https://example.com"
    )

    assert response.response_time >= 0


def test_http_engine_response_headers(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            return FakeResponse(
                headers={
                    "content-type": "application/json",
                    "x-test": "true",
                }
            )

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    response = engine.get(
        "https://example.com"
    )

    assert response.get_header("x-test") == "true"
    assert response.get_content_type() == "application/json"


def test_http_engine_response_cookies(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            return FakeResponse(
                cookies={
                    "session": "abc",
                }
            )

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    response = engine.get(
        "https://example.com"
    )

    assert response.get_cookie("session") == "abc"


def test_http_engine_redirect_response(monkeypatch):
    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def request(self, method, url, **kwargs):
            return FakeResponse(
                status_code=302,
                url="https://example.com/login",
            )

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    response = engine.get(
        "https://example.com"
    )

    assert response.status_code == 302
    assert response.is_redirect
