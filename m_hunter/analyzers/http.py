from dataclasses import dataclass, field
from urllib.parse import parse_qsl

from m_hunter.analyzers.set_cookie import (
    SetCookie,
    SetCookieParser,
)
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class HeaderInfo:
    name: str
    value: str

    @property
    def normalized_name(self) -> str:
        return self.name.strip().lower()


@dataclass(frozen=True)
class CookieInfo:
    name: str
    value: str


@dataclass
class HTTPAnalysis:
    request: HttpRequest
    response: HttpResponse

    request_headers: list[HeaderInfo] = field(
        default_factory=list
    )
    response_headers: list[HeaderInfo] = field(
        default_factory=list
    )
    request_cookies: list[CookieInfo] = field(
        default_factory=list
    )
    response_cookies: list[CookieInfo] = field(
        default_factory=list
    )
    query_parameters: tuple[str, ...] = field(
        default_factory=tuple
    )

    @property
    def status_code(self) -> int:
        return self.response.status_code

    @property
    def content_type(self) -> str | None:
        return self.response.get_content_type()

    @property
    def is_html(self) -> bool:
        return self.response.is_html()

    @property
    def is_json(self) -> bool:
        return self.response.is_json()

    @property
    def redirect_url(self) -> str | None:
        return self.response.get_header("location")

    @property
    def server(self) -> str | None:
        return self.response.get_header("server")

    @property
    def has_cookies(self) -> bool:
        return bool(
            self.request_cookies
            or self.response_cookies
        )

    def request_header(
        self,
        name: str,
    ) -> str | None:
        name = name.lower()

        for header in self.request_headers:
            if header.normalized_name == name:
                return header.value

        return None

    def response_header(
        self,
        name: str,
    ) -> str | None:
        name = name.lower()

        for header in self.response_headers:
            if header.normalized_name == name:
                return header.value

        return None

    def has_response_header(
        self,
        name: str,
    ) -> bool:
        return (
            self.response_header(name) is not None
        )

    def has_request_header(
        self,
        name: str,
    ) -> bool:
        return (
            self.request_header(name) is not None
        )

    def security_headers(self) -> dict[str, str]:
        names = {
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
            "cross-origin-embedder-policy",
        }

        return {
            header.normalized_name: header.value
            for header in self.response_headers
            if header.normalized_name in names
        }

    def cors_headers(self) -> dict[str, str]:
        names = {
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-expose-headers",
            "access-control-max-age",
        }

        return {
            header.normalized_name: header.value
            for header in self.response_headers
            if header.normalized_name in names
        }

    def authentication_headers(self) -> dict[str, str]:
        names = {
            "authorization",
            "proxy-authorization",
            "www-authenticate",
            "proxy-authenticate",
        }

        return {
            header.normalized_name: header.value
            for header in (
                self.request_headers
                + self.response_headers
            )
            if header.normalized_name in names
        }

    def set_cookie_headers(self) -> list[str]:
        return self.response.get_headers_all("Set-Cookie")

    def parsed_set_cookies(self) -> list[SetCookie]:
        parser = SetCookieParser()

        return parser.parse_many(
            self.set_cookie_headers()
        )


class HTTPAnalyzer:
    def analyze(
        self,
        request: HttpRequest,
        response: HttpResponse,
    ) -> HTTPAnalysis:
        if not isinstance(request, HttpRequest):
            raise TypeError(
                "request must be an instance of HttpRequest"
            )

        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        request_headers = [
            HeaderInfo(
                name=name,
                value=value,
            )
            for name, value in request.headers.items()
        ]

        response_headers = [
            HeaderInfo(
                name=name,
                value=value,
            )
            for name, value in response.headers.items()
        ]

        request_cookies = [
            CookieInfo(
                name=name,
                value=value,
            )
            for name, value in request.cookies.items()
        ]

        response_cookies = [
            CookieInfo(
                name=name,
                value=value,
            )
            for name, value in response.cookies.items()
        ]

        query_parameters = tuple(
            name
            for name, _ in parse_qsl(
                request.full_url.split("?", 1)[1]
                if "?" in request.full_url
                else "",
                keep_blank_values=True,
            )
        )

        return HTTPAnalysis(
            request=request,
            response=response,
            request_headers=request_headers,
            response_headers=response_headers,
            request_cookies=request_cookies,
            response_cookies=response_cookies,
            query_parameters=query_parameters,
        )
