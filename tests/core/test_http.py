import httpx

from m_hunter.core.http import HttpEngine
from m_hunter.core.response import HttpResponse


class FakeResponse:
    def __init__(
        self,
        status_code=200,
        url="https://example.com/test",
        headers=None,
        content=b"OK",
        cookies=None,
    ):
        self.status_code = status_code
        self.url = url
        self.headers = headers or {
            "content-type": "text/plain",
            "x-test": "true",
        }
        self.content = content
        self.cookies = cookies or {}


class FakeClient:
    def __init__(
        self,
        response=None,
        exception=None,
    ):
        self.response = response
        self.exception = exception
        self.last_request = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def request(self, method, url, **kwargs):
        self.last_request = {
            "method": method,
            "url": url,
            "kwargs": kwargs,
        }

        if self.exception:
            raise self.exception

        return self.response


def create_fake_client(monkeypatch, response=None, exception=None):
    client = FakeClient(
        response=response,
        exception=exception,
    )

    monkeypatch.setattr(
        "m_hunter.core.http.httpx.Client",
        lambda **kwargs: client,
    )

    return client


def test_http_engine_default_timeout():
    engine = HttpEngine()

    assert engine.timeout == 10.0


def test_http_engine_custom_timeout():
    engine = HttpEngine(timeout=30.0)

    assert engine.timeout == 30.0


def test_request_returns_http_response(monkeypatch):
    response = FakeResponse()

    create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    result = engine.request(
        "GET",
        "https://example.com/test",
    )

    assert isinstance(result, HttpResponse)


def test_request_basic_response(monkeypatch):
    response = FakeResponse(
        status_code=200,
        content=b"Hello M-Hunter",
    )

    create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    result = engine.request(
        "GET",
        "https://example.com/test",
    )

    assert result.status_code == 200
    assert result.url == "https://example.com/test"
    assert result.content == b"Hello M-Hunter"
    assert result.content_length == len(b"Hello M-Hunter")


def test_request_preserves_headers(monkeypatch):
    response = FakeResponse(
        headers={
            "content-type": "application/json",
            "x-custom-header": "test-value",
        },
    )

    create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    result = engine.get(
        "https://example.com/api",
    )

    assert result.headers["content-type"] == "application/json"
    assert result.headers["x-custom-header"] == "test-value"


def test_request_preserves_cookies(monkeypatch):
    response = FakeResponse(
        cookies={
            "session": "abc123",
        },
    )

    create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    result = engine.get(
        "https://example.com",
    )

    assert result.cookies == {
        "session": "abc123",
    }


def test_request_response_time_is_recorded(monkeypatch):
    response = FakeResponse()

    create_fake_client(
        monkeypatch,
        response=response,
    )

    times = iter([10.0, 10.25])

    monkeypatch.setattr(
        "m_hunter.core.http.time.perf_counter",
        lambda: next(times),
    )

    engine = HttpEngine()

    result = engine.get(
        "https://example.com",
    )

    assert result.response_time == 0.25


def test_request_passes_headers(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.get(
        "https://example.com",
        headers={
            "Authorization": "Bearer test",
            "X-Test": "true",
        },
    )

    assert client.last_request["kwargs"]["headers"] == {
        "Authorization": "Bearer test",
        "X-Test": "true",
    }


def test_request_passes_cookies(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.get(
        "https://example.com",
        cookies={
            "session": "abc123",
        },
    )

    assert client.last_request["kwargs"]["cookies"] == {
        "session": "abc123",
    }


def test_request_passes_params(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.get(
        "https://example.com",
        params={
            "q": "test",
            "page": "1",
        },
    )

    assert client.last_request["kwargs"]["params"] == {
        "q": "test",
        "page": "1",
    }


def test_request_passes_data(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.post(
        "https://example.com/login",
        data={
            "username": "test",
            "password": "password",
        },
    )

    assert client.last_request["kwargs"]["data"] == {
        "username": "test",
        "password": "password",
    }


def test_request_passes_json(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.post(
        "https://example.com/api",
        json={
            "name": "M-Hunter",
        },
    )

    assert client.last_request["kwargs"]["json"] == {
        "name": "M-Hunter",
    }


def test_get_method(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.get("https://example.com")

    assert client.last_request["method"] == "GET"


def test_post_method(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.post("https://example.com")

    assert client.last_request["method"] == "POST"


def test_put_method(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.put("https://example.com")

    assert client.last_request["method"] == "PUT"


def test_patch_method(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.patch("https://example.com")

    assert client.last_request["method"] == "PATCH"


def test_delete_method(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.delete("https://example.com")

    assert client.last_request["method"] == "DELETE"


def test_head_method(monkeypatch):
    response = FakeResponse()
    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    engine.head("https://example.com")

    assert client.last_request["method"] == "HEAD"


def test_options_method(monkeypatch):
    response = FakeResponse(
        status_code=204,
        content=b"",
    )

    client = create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    result = engine.options(
        "https://example.com",
    )

    assert client.last_request["method"] == "OPTIONS"
    assert result.status_code == 204


def test_redirect_response(monkeypatch):
    response = FakeResponse(
        status_code=302,
        url="https://example.com/login",
    )

    create_fake_client(
        monkeypatch,
        response=response,
    )

    engine = HttpEngine()

    result = engine.get(
        "https://example.com",
    )

    assert result.status_code == 302
    assert result.url == "https://example.com/login"


def test_timeout_error(monkeypatch):
    create_fake_client(
        monkeypatch,
        exception=httpx.TimeoutException("timeout"),
    )

    engine = HttpEngine()

    try:
        engine.get("https://example.com")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert str(exc) == (
            "HTTP request timed out: https://example.com"
        )


def test_connect_error(monkeypatch):
    create_fake_client(
        monkeypatch,
        exception=httpx.ConnectError("connection failed"),
    )

    engine = HttpEngine()

    try:
        engine.get("https://example.com")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert str(exc) == (
            "Failed to connect to: https://example.com"
        )


def test_network_error(monkeypatch):
    create_fake_client(
        monkeypatch,
        exception=httpx.NetworkError("network failed"),
    )

    engine = HttpEngine()

    try:
        engine.get("https://example.com")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert str(exc) == (
            "Network error while requesting: https://example.com"
        )


def test_http_error(monkeypatch):
    create_fake_client(
        monkeypatch,
        exception=httpx.HTTPError("http error"),
    )

    engine = HttpEngine()

    try:
        engine.get("https://example.com")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert str(exc) == (
            "HTTP error while requesting: https://example.com"
        )
