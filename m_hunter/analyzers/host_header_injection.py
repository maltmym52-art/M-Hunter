from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class HostHeaderInjectionIndicatorType(str, Enum):
    HOST_HEADER = "host_header"
    FORWARDED_HOST = "forwarded_host"
    X_HOST = "x_host"
    FORWARDED_HEADER = "forwarded_header"
    HOST_OVERRIDE = "host_override"
    EXTERNAL_HOST = "external_host"
    ABSOLUTE_URL = "absolute_url"
    PASSWORD_RESET_LINK = "password_reset_link"
    EMAIL_LINK = "email_link"
    CANONICAL_URL = "canonical_url"
    HOST_MISMATCH = "host_mismatch"


@dataclass(frozen=True)
class HostHeaderInjectionIndicator:
    type: HostHeaderInjectionIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class HostHeaderInjectionAnalysis:
    detected: bool
    count: int
    types: tuple[HostHeaderInjectionIndicatorType, ...]
    names: tuple[str, ...]
    indicators: tuple[HostHeaderInjectionIndicator, ...]

    def has_type(
        self,
        indicator_type: HostHeaderInjectionIndicatorType,
    ) -> bool:
        return indicator_type in self.types


class HostHeaderInjectionAnalyzer:
    HOST_HEADERS = {
        "host": HostHeaderInjectionIndicatorType.HOST_HEADER,
        "x-forwarded-host": HostHeaderInjectionIndicatorType.FORWARDED_HOST,
        "x-host": HostHeaderInjectionIndicatorType.X_HOST,
        "forwarded": HostHeaderInjectionIndicatorType.FORWARDED_HEADER,
        "x-original-host": HostHeaderInjectionIndicatorType.HOST_OVERRIDE,
        "x-forwarded-server": HostHeaderInjectionIndicatorType.HOST_OVERRIDE,
    }

    LINK_MARKERS = {
        "password reset": HostHeaderInjectionIndicatorType.PASSWORD_RESET_LINK,
        "reset password": HostHeaderInjectionIndicatorType.PASSWORD_RESET_LINK,
        "reset link": HostHeaderInjectionIndicatorType.PASSWORD_RESET_LINK,
        "email link": HostHeaderInjectionIndicatorType.EMAIL_LINK,
        "canonical": HostHeaderInjectionIndicatorType.CANONICAL_URL,
    }

    def _external_host(
        self,
        value: str,
        expected_host: str | None,
    ) -> bool:
        if expected_host is None:
            return False

        candidate = value.strip()

        if "://" in candidate:
            parsed = urlparse(candidate)
            candidate = parsed.hostname or candidate

        candidate = candidate.split(",", 1)[0].strip()
        candidate = candidate.split(":", 1)[0].lower()

        return candidate != expected_host.lower()

    def analyze(
        self,
        *,
        headers: dict[str, str] | None = None,
        response_headers: dict[str, str] | None = None,
        response_body: str | bytes | None = None,
        expected_host: str | None = None,
        request_host: str | None = None,
        response_host: str | None = None,
    ) -> HostHeaderInjectionAnalysis:
        if headers is not None and not isinstance(headers, dict):
            raise TypeError("headers must be a dictionary or None")

        if response_headers is not None and not isinstance(
            response_headers,
            dict,
        ):
            raise TypeError(
                "response_headers must be a dictionary or None"
            )

        if response_body is not None and not isinstance(
            response_body,
            (str, bytes),
        ):
            raise TypeError(
                "response_body must be a string, bytes, or None"
            )

        for value, name in (
            (expected_host, "expected_host"),
            (request_host, "request_host"),
            (response_host, "response_host"),
        ):
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{name} must be a string or None")

        indicators: list[HostHeaderInjectionIndicator] = []

        if headers:
            for name, value in headers.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise TypeError(
                        "headers must contain string names and values"
                    )

                lowered = name.lower()

                if lowered in self.HOST_HEADERS:
                    indicator_type = self.HOST_HEADERS[lowered]

                    indicators.append(
                        HostHeaderInjectionIndicator(
                            indicator_type,
                            f"Host-related request header detected: {name}.",
                            name,
                            value,
                        )
                    )

                    if self._external_host(value, expected_host):
                        indicators.append(
                            HostHeaderInjectionIndicator(
                                HostHeaderInjectionIndicatorType.EXTERNAL_HOST,
                                (
                                    "Host-related header differs from "
                                    "the expected host."
                                ),
                                name,
                                value,
                            )
                        )

                if lowered == "host" and request_host is not None:
                    if value.lower() != request_host.lower():
                        indicators.append(
                            HostHeaderInjectionIndicator(
                                HostHeaderInjectionIndicatorType.HOST_MISMATCH,
                                "Request Host differs from supplied request host.",
                                name,
                                value,
                            )
                        )

        if response_headers:
            for name, value in response_headers.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise TypeError(
                        "response_headers must contain string names and values"
                    )

                lowered = name.lower()

                if lowered in {"location", "content-location"}:
                    indicators.append(
                        HostHeaderInjectionIndicator(
                            HostHeaderInjectionIndicatorType.ABSOLUTE_URL,
                            f"Absolute URL response header detected: {name}.",
                            name,
                            value,
                        )
                    )

                    if self._external_host(value, expected_host):
                        indicators.append(
                            HostHeaderInjectionIndicator(
                                HostHeaderInjectionIndicatorType.EXTERNAL_HOST,
                                (
                                    "Response URL uses a host different "
                                    "from the expected host."
                                ),
                                name,
                                value,
                            )
                        )

                if lowered == "link" and "http" in value.lower():
                    indicators.append(
                        HostHeaderInjectionIndicator(
                            HostHeaderInjectionIndicatorType.ABSOLUTE_URL,
                            "Absolute URL found in Link response header.",
                            name,
                            value,
                        )
                    )

        if request_host is not None and response_host is not None:
            if request_host.lower() != response_host.lower():
                indicators.append(
                    HostHeaderInjectionIndicator(
                        HostHeaderInjectionIndicatorType.HOST_MISMATCH,
                        "Request and response hosts differ.",
                        "host",
                        f"{request_host} -> {response_host}",
                    )
                )

        if response_body is not None:
            body = (
                response_body.decode("utf-8", errors="replace")
                if isinstance(response_body, bytes)
                else response_body
            )

            lowered_body = body.lower()

            for marker, indicator_type in self.LINK_MARKERS.items():
                if marker in lowered_body:
                    indicators.append(
                        HostHeaderInjectionIndicator(
                            indicator_type,
                            f"Host-related link marker detected: {marker}.",
                            None,
                            marker,
                        )
                    )

            if "http://" in lowered_body or "https://" in lowered_body:
                indicators.append(
                    HostHeaderInjectionIndicator(
                        HostHeaderInjectionIndicatorType.ABSOLUTE_URL,
                        "Absolute URL detected in response body.",
                    )
                )

                if expected_host:
                    expected = expected_host.lower()
                    for token in (
                        body.replace('"', " ")
                        .replace("'", " ")
                        .replace("<", " ")
                        .replace(">", " ")
                    ).split():
                        if token.lower().startswith(
                            ("http://", "https://")
                        ):
                            parsed = urlparse(token.rstrip(".,);"))
                            if (
                                parsed.hostname
                                and parsed.hostname.lower() != expected
                            ):
                                indicators.append(
                                    HostHeaderInjectionIndicator(
                                        HostHeaderInjectionIndicatorType.EXTERNAL_HOST,
                                        (
                                            "Response body contains an "
                                            "absolute URL using a different host."
                                        ),
                                        None,
                                        token,
                                    )
                                )
                                break

        unique_types: list[HostHeaderInjectionIndicatorType] = []
        names: list[str] = []

        for indicator in indicators:
            if indicator.type not in unique_types:
                unique_types.append(indicator.type)

            if indicator.name is not None and indicator.name not in names:
                names.append(indicator.name)

        return HostHeaderInjectionAnalysis(
            detected=bool(indicators),
            count=len(indicators),
            types=tuple(unique_types),
            names=tuple(names),
            indicators=tuple(indicators),
        )
