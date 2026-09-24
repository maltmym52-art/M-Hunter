from dataclasses import dataclass

import pytest

from m_hunter.core.response import HttpResponse
from m_hunter.recon.asset import Asset
from m_hunter.recon.probe import (
    HTTPProbe,
    PROBEABLE_ASSET_TYPES,
)


class FakeHttp:
    def __init__(
        self,
        response=None,
        error=None,
    ):
        self.response = response
        self.error = error
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(
            {
                "url": url,
                "kwargs": kwargs,
            }
        )

        if self.error is not None:
            raise self.error

        return self.response


def make_response(
    *,
    status_code=200,
    url="https://example.com",
    headers=None,
    content=b"",
    response_time=0.25,
    cookies=None,
):
    return HttpResponse(
        status_code=status_code,
        url=url,
        headers=headers or {},
        content=content,
        cookies=cookies or {},
        response_time=response_time,
        content_length=len(content),
    )


def make_asset(
    value="example.com",
    asset_type="domain",
):
    return Asset(
        value=value,
        asset_type=asset_type,
    )


def test_probeable_asset_types():
    assert {
        "domain",
        "subdomain",
        "url",
        "endpoint",
        "api",
    } == PROBEABLE_ASSET_TYPES


def test_probe_requires_asset():
    probe = HTTPProbe(
        http=FakeHttp()
    )

    with pytest.raises(
        TypeError,
        match="asset must be an instance of Asset",
    ):
        probe.probe(object())


def test_empty_scheme_is_rejected():
    with pytest.raises(
        ValueError,
        match="scheme must not be empty",
    ):
        HTTPProbe(
            http=FakeHttp(),
            scheme="",
        )


def test_default_scheme_is_https():
    http = FakeHttp(
        response=make_response()
    )

    probe = HTTPProbe(
        http=http
    )

    probe.probe(
        make_asset()
    )

    assert http.calls[0]["url"] == (
        "https://example.com"
    )


def test_custom_scheme_is_used():
    http = FakeHttp(
        response=make_response(
            url="http://example.com"
        )
    )

    probe = HTTPProbe(
        http=http,
        scheme="http://",
    )

    probe.probe(
        make_asset()
    )

    assert http.calls[0]["url"] == (
        "http://example.com"
    )


def test_existing_https_url_is_preserved():
    http = FakeHttp(
        response=make_response()
    )

    probe = HTTPProbe(
        http=http
    )

    probe.probe(
        make_asset(
            value="https://example.com/path",
            asset_type="url",
        )
    )

    assert http.calls[0]["url"] == (
        "https://example.com/path"
    )


def test_existing_http_url_is_preserved():
    http = FakeHttp(
        response=make_response(
            url="http://example.com"
        )
    )

    probe = HTTPProbe(
        http=http
    )

    probe.probe(
        make_asset(
            value="http://example.com",
            asset_type="url",
        )
    )

    assert http.calls[0]["url"] == (
        "http://example.com"
    )


def test_probe_success():
    response = make_response(
        status_code=200,
        url="https://example.com",
        headers={
            "content-type": "text/html",
        },
        content=b"<html><body>Hello</body></html>",
    )

    http = FakeHttp(
        response=response
    )

    probe = HTTPProbe(
        http=http
    )

    asset = make_asset()

    result = probe.probe(asset)

    assert result.asset_id == asset.id
    assert result.asset is asset
    assert result.alive is True
    assert result.status_code == 200
    assert result.url == "https://example.com"
    assert result.content_type == "text/html"
    assert result.content_length == len(response.content)
    assert result.response_time == 0.25
    assert result.error is None


def test_success_marks_asset_alive():
    http = FakeHttp(
        response=make_response()
    )

    probe = HTTPProbe(
        http=http
    )

    asset = make_asset()

    assert asset.alive is False

    result = probe.probe(asset)

    assert result.alive is True
    assert asset.alive is True


def test_probe_extracts_server_header():
    response = make_response(
        headers={
            "server": "example-server",
        }
    )

    http = FakeHttp(
        response=response
    )

    result = HTTPProbe(
        http=http
    ).probe(
        make_asset()
    )

    assert result.server == "example-server"


def test_probe_extracts_content_type():
    response = make_response(
        headers={
            "Content-Type": "text/html; charset=utf-8",
        }
    )

    http = FakeHttp(
        response=response
    )

    result = HTTPProbe(
        http=http
    ).probe(
        make_asset()
    )

    assert result.content_type == "text/html"


def test_probe_extracts_redirect():
    response = make_response(
        status_code=302,
        headers={
            "Location": "https://www.example.com",
        },
        url="https://example.com",
    )

    http = FakeHttp(
        response=response
    )

    result = HTTPProbe(
        http=http
    ).probe(
        make_asset()
    )

    assert result.alive is True
    assert result.status_code == 302
    assert result.redirect_url == (
        "https://www.example.com"
    )


def test_probe_extracts_html_title():
    response = make_response(
        headers={
            "content-type": "text/html",
        },
        content=(
            b"<html>"
            b"<head>"
            b"<title>Example Site</title>"
            b"</head>"
            b"</html>"
        ),
    )

    http = FakeHttp(
        response=response
    )

    result = HTTPProbe(
        http=http
    ).probe(
        make_asset()
    )

    assert result.title == "Example Site"


def test_title_extraction_is_case_insensitive():
    response = make_response(
        headers={
            "content-type": "text/html",
        },
        content=(
            b"<HTML>"
            b"<HEAD>"
            b"<TITLE>Example</TITLE>"
            b"</HEAD>"
            b"</HTML>"
        ),
    )

    http = FakeHttp(
        response=response
    )

    result = HTTPProbe(
        http=http
    ).probe(
        make_asset()
    )

    assert result.title == "Example"


def test_missing_title_returns_none():
    response = make_response(
        headers={
            "content-type": "text/html",
        },
        content=b"<html><body>No title</body></html>",
    )

    http = FakeHttp(
        response=response
    )

    result = HTTPProbe(
        http=http
    ).probe(
        make_asset()
    )

    assert result.title is None


def test_empty_title_returns_none():
    response = make_response(
        headers={
            "content-type": "text/html",
        },
        content=b"<title>   </title>",
    )

    http = FakeHttp(
        response=response
    )

    result = HTTPProbe(
        http=http
    ).probe(
        make_asset()
    )

    assert result.title is None


def test_non_html_response_has_no_title():
    response = make_response(
        headers={
            "content-type": "application/json",
        },
        content=b'{"status":"ok"}',
    )

    http = FakeHttp(
        response=response
    )

    result = HTTPProbe(
        http=http
    ).probe(
        make_asset()
    )

    assert result.title is None


@pytest.mark.parametrize(
    "status_code",
    [
        200,
        201,
        204,
        301,
        302,
        400,
        401,
        403,
        404,
        500,
    ],
)
def test_http_statuses_are_recorded(status_code):
    response = make_response(
        status_code=status_code
    )

    http = FakeHttp(
        response=response
    )

    result = HTTPProbe(
        http=http
    ).probe(
        make_asset()
    )

    assert result.alive is True
    assert result.status_code == status_code


@pytest.mark.parametrize(
    "asset_type",
    [
        "ip",
        "javascript",
    ],
)
def test_non_probeable_asset_types_are_rejected(
    asset_type,
):
    http = FakeHttp()

    probe = HTTPProbe(
        http=http
    )

    asset = make_asset(
        value="192.0.2.1",
        asset_type=asset_type,
    )

    result = probe.probe(asset)

    assert result.alive is False
    assert result.status_code is None
    assert result.url is None
    assert "not probeable" in result.error
    assert http.calls == []


def test_http_error_returns_failed_result():
    http = FakeHttp(
        error=RuntimeError(
            "HTTP request timed out"
        )
    )

    probe = HTTPProbe(
        http=http
    )

    asset = make_asset()

    result = probe.probe(asset)

    assert result.alive is False
    assert result.status_code is None
    assert result.error == (
        "HTTP request timed out"
    )


def test_connection_error_returns_failed_result():
    http = FakeHttp(
        error=RuntimeError(
            "Failed to connect"
        )
    )

    result = HTTPProbe(
        http=http
    ).probe(
        make_asset()
    )

    assert result.alive is False
    assert result.error == (
        "Failed to connect"
    )


def test_probe_calls_http_once():
    http = FakeHttp(
        response=make_response()
    )

    probe = HTTPProbe(
        http=http
    )

    probe.probe(
        make_asset()
    )

    assert len(http.calls) == 1


def test_subdomain_is_probeable():
    http = FakeHttp(
        response=make_response(
            url="https://api.example.com"
        )
    )

    asset = make_asset(
        value="api.example.com",
        asset_type="subdomain",
    )

    result = HTTPProbe(
        http=http
    ).probe(asset)

    assert result.alive is True
    assert result.url == (
        "https://api.example.com"
    )


def test_endpoint_is_probeable():
    http = FakeHttp(
        response=make_response(
            url="https://example.com/api",
        )
    )

    asset = make_asset(
        value="https://example.com/api",
        asset_type="endpoint",
    )

    result = HTTPProbe(
        http=http
    ).probe(asset)

    assert result.alive is True


def test_api_is_probeable():
    http = FakeHttp(
        response=make_response(
            url="https://example.com/api",
            headers={
                "content-type": "application/json",
            },
        )
    )

    asset = make_asset(
        value="https://example.com/api",
        asset_type="api",
    )

    result = HTTPProbe(
        http=http
    ).probe(asset)

    assert result.alive is True
    assert result.content_type == (
        "application/json"
    )
