import httpx
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
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.request_calls = []
        self.closed = False

        FakeClient.instances.append(self)

    def request(self, method, url, **kwargs):
        self.request_calls.append(
            {
                "method": method,
                "url": url,
                "kwargs": kwargs,
            }
        )

        return FakeResponse()

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def reset_fake_clients():
    FakeClient.instances.clear()


def patch_client(monkeypatch):
    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        FakeClient,
    )


def test_http_engine_defaults():
    engine = HttpEngine()

    assert engine.timeout == 10.0
    assert engine.follow_redirects is True
    assert engine.user_agent == "M-Hunter/0.1.0"
    assert engine.is_closed is False

    engine.close()


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

    engine.close()


def test_http_engine_creates_one_client(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    assert len(FakeClient.instances) == 1

    engine.close()


def test_http_engine_client_uses_settings(monkeypatch):
    patch_client(monkeypatch)

    settings = HttpSettings(
        timeout=25.0,
        follow_redirects=False,
        user_agent="Test-Agent/2.0",
    )

    engine = HttpEngine(settings)

    client = FakeClient.instances[0]

    assert client.kwargs["timeout"] == 25.0
    assert client.kwargs["follow_redirects"] is False
    assert client.kwargs["headers"] == {
        "User-Agent": "Test-Agent/2.0",
    }

    engine.close()


def test_http_engine_reuses_client(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    engine.get("https://example.com/one")
    engine.get("https://example.com/two")

    assert len(FakeClient.instances) == 1

    client = FakeClient.instances[0]

    assert len(client.request_calls) == 2
    assert client.request_calls[0]["url"] == (
        "https://example.com/one"
    )
    assert client.request_calls[1]["url"] == (
        "https://example.com/two"
    )

    engine.close()


def test_http_engine_creates_response(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    response = engine.get(
        "https://example.com/test"
    )

    assert response.status_code == 200
    assert response.url == "https://example.com/final"
    assert response.content == b"OK"
    assert response.content_length == 2
    assert response.get_content_type() == "text/plain"

    engine.close()


def test_http_engine_passes_request_headers(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    engine.get(
        "https://example.com",
        headers={
            "Authorization": "Bearer test",
        },
    )

    client = FakeClient.instances[0]

    assert client.request_calls[0]["kwargs"]["headers"] == {
        "Authorization": "Bearer test",
    }

    engine.close()


def test_http_engine_passes_cookies(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    engine.get(
        "https://example.com",
        cookies={
            "session": "abc",
        },
    )

    client = FakeClient.instances[0]

    headers = client.request_calls[0]["kwargs"]["headers"]

    assert "session=abc" in headers["cookie"]


def test_http_engine_passes_params(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    engine.get(
        "https://example.com",
        params={
            "page": "1",
        },
    )

    client = FakeClient.instances[0]

    assert client.request_calls[0]["kwargs"]["params"] == {
        "page": "1",
    }

    engine.close()


def test_http_engine_allows_per_request_redirect_override(monkeypatch):
    patch_client(monkeypatch)
    engine = HttpEngine()

    engine.get("https://example.com/redirect", follow_redirects=False)
    engine.get("https://example.com/default")

    calls = FakeClient.instances[0].request_calls
    assert calls[0]["kwargs"]["follow_redirects"] is False
    assert "follow_redirects" not in calls[1]["kwargs"]
    engine.close()


def test_http_engine_passes_data(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    engine.post(
        "https://example.com",
        data={
            "username": "test",
        },
    )

    client = FakeClient.instances[0]

    assert client.request_calls[0]["kwargs"]["data"] == {
        "username": "test",
    }

    engine.close()


def test_http_engine_passes_json(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    engine.post(
        "https://example.com",
        json={
            "username": "test",
        },
    )

    client = FakeClient.instances[0]

    assert client.request_calls[0]["kwargs"]["json"] == {
        "username": "test",
    }

    engine.close()


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
    patch_client(monkeypatch)

    engine = HttpEngine()

    getattr(engine, method)(
        "https://example.com"
    )

    client = FakeClient.instances[0]

    assert client.request_calls[0]["method"] == method.upper()

    engine.close()


def test_http_engine_handles_timeout(monkeypatch):
    class Client(FakeClient):
        def request(self, method, url, **kwargs):
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

    engine.close()


def test_http_engine_handles_connect_error(monkeypatch):
    class Client(FakeClient):
        def request(self, method, url, **kwargs):
            raise httpx.ConnectError(
                "connection failed"
            )

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

    engine.close()


def test_http_engine_handles_network_error(monkeypatch):
    class Client(FakeClient):
        def request(self, method, url, **kwargs):
            raise httpx.NetworkError(
                "network failed"
            )

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

    engine.close()


def test_http_engine_handles_http_error(monkeypatch):
    class Client(FakeClient):
        def request(self, method, url, **kwargs):
            raise httpx.HTTPError(
                "http failed"
            )

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

    engine.close()


def test_http_engine_response_timing(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    response = engine.get(
        "https://example.com"
    )

    assert response.response_time >= 0

    engine.close()


def test_http_engine_response_headers(monkeypatch):
    class Client(FakeClient):
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

    engine.close()


def test_http_engine_response_cookies(monkeypatch):
    class Client(FakeClient):
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

    engine.close()


def test_http_engine_redirect_response(monkeypatch):
    class Client(FakeClient):
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

    engine.close()


def test_http_engine_close_closes_client(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    client = FakeClient.instances[0]

    assert client.closed is False
    assert engine.is_closed is False

    engine.close()

    assert client.closed is True
    assert engine.is_closed is True


def test_http_engine_close_is_idempotent(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    client = FakeClient.instances[0]

    engine.close()
    engine.close()

    assert client.closed is True
    assert engine.is_closed is True


def test_http_engine_rejects_request_after_close(monkeypatch):
    patch_client(monkeypatch)

    engine = HttpEngine()

    engine.close()

    with pytest.raises(
        RuntimeError,
        match="HttpEngine is closed",
    ):
        engine.get("https://example.com")


def test_http_engine_context_manager(monkeypatch):
    patch_client(monkeypatch)

    with HttpEngine() as engine:
        assert engine.is_closed is False

    assert engine.is_closed is True
    assert FakeClient.instances[0].closed is True


def test_http_engine_context_manager_closes_after_exception(
    monkeypatch,
):
    patch_client(monkeypatch)

    with pytest.raises(RuntimeError):
        with HttpEngine() as engine:
            raise RuntimeError("test error")

    assert engine.is_closed is True
    assert FakeClient.instances[0].closed is True


def test_http_engine_preserves_repeated_headers(monkeypatch):
    class Client(FakeClient):
        def request(self, method, url, **kwargs):
            return FakeResponse(
                headers=httpx.Headers([
                    (
                        "set-cookie",
                        "session=abc; Secure; HttpOnly",
                    ),
                    (
                        "set-cookie",
                        "theme=dark; Path=/",
                    ),
                    (
                        "content-type",
                        "text/plain",
                    ),
                ])
            )

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        Client,
    )

    engine = HttpEngine()

    response = engine.get(
        "https://example.com"
    )

    assert response.repeated_headers == {
        "set-cookie": [
            "theme=dark; Path=/",
        ],
    }

    assert response.get_headers_all("set-cookie") == [
        "session=abc; Secure; HttpOnly",
        "theme=dark; Path=/",
    ]

    engine.close()
