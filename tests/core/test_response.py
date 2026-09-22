from m_hunter.core.response import HttpResponse


def create_response(
    status_code: int = 200,
    content_type: str = "text/html",
    content: bytes = b"<html>Hello</html>",
) -> HttpResponse:
    return HttpResponse(
        status_code=status_code,
        url="https://example.com",
        headers={
            "Content-Type": content_type,
        },
        content=content,
        cookies={
    "session": "abc123",
},
        response_time=0.5,
        content_length=len(content),
    )


def test_is_success():
    response = create_response(status_code=200)

    assert response.is_success is True


def test_is_redirect():
    response = create_response(status_code=302)

    assert response.is_redirect is True


def test_is_client_error():
    response = create_response(status_code=404)

    assert response.is_client_error is True


def test_is_server_error():
    response = create_response(status_code=500)

    assert response.is_server_error is True


def test_status_category():
    response = create_response(status_code=200)

    assert response.status_category == "success"

def test_get_header_case_insensitive():
    response = create_response()

    assert response.get_header("content-type") == "text/html"
    assert response.get_header("Content-Type") == "text/html"
    assert response.get_header("CONTENT-TYPE") == "text/html"


def test_get_cookie():
    response = create_response()

    assert response.get_cookie("session") == "abc123"
    assert response.get_cookie("missing") is None


def test_content_type_and_html():
    response = create_response(
        content_type="text/html; charset=utf-8"
    )

    assert response.get_content_type() == "text/html"
    assert response.is_html() is True
    assert response.is_text() is True
    assert response.is_json() is False


def test_json_response():
    response = create_response(
        content_type="application/json",
        content=b'{"status": "ok", "count": 5}',
    )

    assert response.is_json() is True
    assert response.json() == {
        "status": "ok",
        "count": 5,
    }


def test_json_rejects_non_json():
    response = create_response(
        content_type="text/html",
        content=b"<html>Hello</html>",
    )

    try:
        response.json()
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for non-JSON response")


def test_get_headers_returns_copy():
    response = create_response()

    headers = response.get_headers()

    assert headers == {
        "Content-Type": "text/html",
    }

    headers["X-Test"] = "value"

    assert response.get_header("X-Test") is None
