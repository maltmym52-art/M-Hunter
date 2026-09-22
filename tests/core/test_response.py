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


def test_is_text_for_text_types():
    text_types = [
        "text/plain",
        "text/css",
        "application/javascript",
        "application/xml",
        "application/xhtml+xml",
    ]

    for content_type in text_types:
        response = create_response(content_type=content_type)

        assert response.is_text() is True


def test_missing_content_type():
    response = create_response()

    response.headers.clear()

    assert response.get_content_type() is None
    assert response.is_text() is False
    assert response.is_html() is False
    assert response.is_json() is False


def test_status_category_boundaries():
    assert create_response(status_code=100).status_category == "informational"
    assert create_response(status_code=299).status_category == "success"
    assert create_response(status_code=300).status_category == "redirect"
    assert create_response(status_code=399).status_category == "redirect"
    assert create_response(status_code=400).status_category == "client_error"
    assert create_response(status_code=499).status_category == "client_error"
    assert create_response(status_code=500).status_category == "server_error"
    assert create_response(status_code=599).status_category == "server_error"


def test_invalid_json():
    response = create_response(
        content_type="application/json",
        content=b'{"status": invalid}',
    )

    try:
        response.json()
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for invalid JSON")


def test_text_decoding_invalid_utf8():
    response = create_response(
        content=b"Hello \xff World",
    )

    assert response.text == "Hello � World"


def test_empty_cookie_value():
    response = create_response()

    response.cookies["empty"] = ""

    assert response.get_cookie("empty") == ""


def test_content_type_normalization():
    response = create_response(
        content_type="  Application/JSON ; charset=UTF-8  "
    )

    assert response.get_content_type() == "application/json"
    assert response.is_json() is True


def test_missing_header():
    response = create_response()

    assert response.get_header("X-Missing-Header") is None


def test_is_html_false_for_non_html():
    response = create_response(
        content_type="application/json"
    )

    assert response.is_html() is False


def test_binary_content_is_not_text():
    response = create_response(
        content_type="application/octet-stream",
        content=b"\x00\x01\x02\x03",
    )

    assert response.is_text() is False
