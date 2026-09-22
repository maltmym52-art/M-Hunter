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
        cookies={},
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
