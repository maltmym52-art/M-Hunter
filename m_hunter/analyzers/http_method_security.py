from dataclasses import dataclass
from enum import Enum

from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse


class HTTPMethodSecurityIndicatorType(str, Enum):
    DANGEROUS_METHOD = "dangerous_method"
    TRACE_ENABLED = "trace_enabled"
    TRACK_ENABLED = "track_enabled"
    CONNECT_ENABLED = "connect_enabled"
    UNEXPECTED_PUT = "unexpected_put"
    UNEXPECTED_DELETE = "unexpected_delete"
    METHOD_OVERRIDE_HEADER = "method_override_header"
    METHOD_OVERRIDE_PARAMETER = "method_override_parameter"
    OPTIONS_EXPOSURE = "options_exposure"
    ALLOW_HEADER = "allow_header"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    METHOD_INCONSISTENCY = "method_inconsistency"


@dataclass(frozen=True)
class HTTPMethodSecurityIndicator:
    type: HTTPMethodSecurityIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class HTTPMethodSecurityAnalysis:
    indicators: tuple[HTTPMethodSecurityIndicator, ...]

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> set[HTTPMethodSecurityIndicatorType]:
        return {
            indicator.type
            for indicator in self.indicators
        }

    @property
    def names(self) -> set[str]:
        return {
            indicator.name
            for indicator in self.indicators
            if indicator.name is not None
        }

    def has_type(
        self,
        indicator_type: HTTPMethodSecurityIndicatorType,
    ) -> bool:
        return indicator_type in self.types


class HTTPMethodSecurityAnalyzer:
    DANGEROUS_METHODS = {
        "TRACE",
        "TRACK",
        "CONNECT",
    }

    OVERRIDE_HEADERS = {
        "x-http-method-override",
        "x-http-method",
        "x-method-override",
    }

    OVERRIDE_PARAMETERS = {
        "_method",
        "method",
        "http_method",
        "http-method",
    }

    def analyze(
        self,
        *,
        request: HttpRequest,
        response: HttpResponse,
    ) -> HTTPMethodSecurityAnalysis:
        if not isinstance(request, HttpRequest):
            raise TypeError("request must be an HttpRequest")

        if not isinstance(response, HttpResponse):
            raise TypeError("response must be an HttpResponse")

        indicators: list[HTTPMethodSecurityIndicator] = []

        def add(
            indicator_type: HTTPMethodSecurityIndicatorType,
            evidence: str,
            name: str | None = None,
            value: str | None = None,
        ) -> None:
            indicators.append(
                HTTPMethodSecurityIndicator(
                    type=indicator_type,
                    evidence=evidence,
                    name=name,
                    value=value,
                )
            )

        method = request.method.upper()

        if method in self.DANGEROUS_METHODS:
            add(
                HTTPMethodSecurityIndicatorType.DANGEROUS_METHOD,
                f"Potentially dangerous HTTP method observed: {method}.",
                value=method,
            )

            if method == "TRACE" and response.status_code < 400:
                add(
                    HTTPMethodSecurityIndicatorType.TRACE_ENABLED,
                    "TRACE request received a successful or redirect response.",
                    value=str(response.status_code),
                )

            if method == "TRACK" and response.status_code < 400:
                add(
                    HTTPMethodSecurityIndicatorType.TRACK_ENABLED,
                    "TRACK request received a successful or redirect response.",
                    value=str(response.status_code),
                )

            if method == "CONNECT" and response.status_code < 400:
                add(
                    HTTPMethodSecurityIndicatorType.CONNECT_ENABLED,
                    "CONNECT request received a successful or redirect response.",
                    value=str(response.status_code),
                )

        if method == "PUT":
            add(
                HTTPMethodSecurityIndicatorType.UNEXPECTED_PUT,
                "PUT method was observed and requires authorization review.",
                value=method,
            )

        if method == "DELETE":
            add(
                HTTPMethodSecurityIndicatorType.UNEXPECTED_DELETE,
                "DELETE method was observed and requires authorization review.",
                value=method,
            )

        for name, value in request.headers.items():
            normalized = name.strip().lower()

            if normalized in self.OVERRIDE_HEADERS:
                add(
                    HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_HEADER,
                    f"HTTP method override header detected: {name}.",
                    name=name,
                    value=value,
                )

        for name in request.params:
            normalized = name.strip().lower()

            if normalized in self.OVERRIDE_PARAMETERS:
                add(
                    HTTPMethodSecurityIndicatorType.METHOD_OVERRIDE_PARAMETER,
                    f"HTTP method override parameter detected: {name}.",
                    name=name,
                    value=request.params[name],
                )

        if method == "OPTIONS":
            add(
                HTTPMethodSecurityIndicatorType.OPTIONS_EXPOSURE,
                "OPTIONS method was observed.",
                value=method,
            )

        allow = response.get_header("allow")

        if allow is not None:
            add(
                HTTPMethodSecurityIndicatorType.ALLOW_HEADER,
                "Allow response header exposes supported HTTP methods.",
                name="Allow",
                value=allow,
            )

        if response.status_code == 405:
            add(
                HTTPMethodSecurityIndicatorType.METHOD_NOT_ALLOWED,
                "Server returned 405 Method Not Allowed.",
                value=method,
            )

        return HTTPMethodSecurityAnalysis(
            indicators=tuple(indicators),
        )
