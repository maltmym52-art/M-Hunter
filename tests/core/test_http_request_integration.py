import httpx
import pytest

from m_hunter.core.http import HttpEngine
from m_hunter.core.request import HttpRequest


def make_response(
    request: httpx.Request,
    *,
    status_code: int = 200,
    content: bytes = b"OK",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        headers=headers or {},
        content=content,
        request=request,
    )


def test_send_accepts_http_request():
    engine = HttpEngine()

    def handler(request: httpx.Request) -> httpx.Response:
        return make_response(
            request,
            content=b"hello",
        )

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        headers={
            "User-Agent": engine.user_agent,
        },
    )

    request = HttpRequest(
        method="GET",
        url="https://example.com",
    )

    response = engine.send(request)

    assert response.status_code == 200
    assert response.url == "https://example.com"
    assert response.content == b"hello"

    engine.close()


def test_send_uses_request_method():
    engine = HttpEngine()
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        return make_response(request)

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    request = HttpRequest(
        method="POST",
        url="https://example.com",
    )

    engine.send(request)

    assert captured["method"] == "POST"

    engine.close()


def test_send_uses_request_headers():
    engine = HttpEngine()
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["header"] = request.headers["X-Test"]
        return make_response(request)

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    request = HttpRequest(
        method="GET",
        url="https://example.com",
        headers={
            "X-Test": "m-hunter",
        },
    )

    engine.send(request)

    assert captured["header"] == "m-hunter"

    engine.close()


def test_send_uses_request_cookies():
    engine = HttpEngine()
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["cookie"] = request.headers["cookie"]
        return make_response(request)

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    request = HttpRequest(
        method="GET",
        url="https://example.com",
        cookies={
            "session": "abc123",
        },
    )

    engine.send(request)

    assert "session=abc123" in captured["cookie"]

    engine.close()


def test_send_uses_request_params():
    engine = HttpEngine()
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return make_response(request)

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    request = HttpRequest(
        method="GET",
        url="https://example.com/search",
        params={
            "q": "test",
            "page": "1",
        },
    )

    engine.send(request)

    assert "q=test" in captured["url"]
    assert "page=1" in captured["url"]

    engine.close()


def test_send_uses_request_body():
    engine = HttpEngine()
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        return make_response(request)

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    request = HttpRequest(
        method="POST",
        url="https://example.com",
        body="hello",
    )

    engine.send(request)

    assert captured["body"] == b"hello"

    engine.close()


def test_send_rejects_invalid_request_type():
    engine = HttpEngine()

    with pytest.raises(TypeError, match="HttpRequest"):
        engine.send("not a request")

    engine.close()


def test_send_preserves_response_metadata():
    engine = HttpEngine()

    def handler(request: httpx.Request) -> httpx.Response:
        return make_response(
            request,
            status_code=201,
            content=b"created",
            headers={
                "Content-Type": "text/plain",
                "X-Test": "value",
            },
        )

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    request = HttpRequest(
        method="POST",
        url="https://example.com",
        body="data",
    )

    response = engine.send(request)

    assert response.status_code == 201
    assert response.content == b"created"
    assert response.get_header("content-type") == "text/plain"
    assert response.get_header("x-test") == "value"
    assert response.content_length == len(b"created")

    engine.close()


def test_send_works_with_context_manager():
    def handler(request: httpx.Request) -> httpx.Response:
        return make_response(request)

    with HttpEngine() as engine:
        engine._client = httpx.Client(
            transport=httpx.MockTransport(handler),
        )

        request = HttpRequest(
            method="GET",
            url="https://example.com",
        )

        response = engine.send(request)

        assert response.status_code == 200

    assert engine.is_closed


def test_existing_request_api_still_works():
    engine = HttpEngine()

    def handler(request: httpx.Request) -> httpx.Response:
        return make_response(
            request,
            content=b"legacy-api",
        )

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    response = engine.request(
        "GET",
        "https://example.com",
    )

    assert response.status_code == 200
    assert response.content == b"legacy-api"

    engine.close()


def test_existing_get_api_still_works():
    engine = HttpEngine()

    def handler(request: httpx.Request) -> httpx.Response:
        return make_response(request)

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    response = engine.get("https://example.com")

    assert response.status_code == 200

    engine.close()


def test_send_rejects_request_after_engine_closed():
    engine = HttpEngine()
    engine.close()

    request = HttpRequest(
        method="GET",
        url="https://example.com",
    )

    with pytest.raises(RuntimeError, match="HttpEngine is closed"):
        engine.send(request)


def test_send_cookie_header_preserves_request_cookie():
    engine = HttpEngine()
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["cookie"] = request.headers["cookie"]
        return make_response(request)

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    request = HttpRequest(
        method="GET",
        url="https://example.com",
        cookies={
            "session": "abc123",
            "user": "m-hunter",
        },
    )

    engine.send(request)

    assert "session=abc123" in captured["cookie"]
    assert "user=m-hunter" in captured["cookie"]

    engine.close()


def test_send_raw_body_uses_content():
    engine = HttpEngine()
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        return make_response(request)

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
    )

    request = HttpRequest(
        method="POST",
        url="https://example.com",
        body=b"raw-body",
    )

    engine.send(request)

    assert captured["body"] == b"raw-body"

    engine.close()
