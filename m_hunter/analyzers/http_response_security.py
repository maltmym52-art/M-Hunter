from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ipaddress
import re


_IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)


class HttpResponseSecurityIndicatorType(str, Enum):
    SERVER_DISCLOSURE = "server_disclosure"
    SERVER_VERSION_DISCLOSURE = "server_version_disclosure"

    X_POWERED_BY = "x_powered_by"
    TECHNOLOGY_DISCLOSURE = "technology_disclosure"

    DEBUG_DISCLOSURE = "debug_disclosure"
    STACK_TRACE_DISCLOSURE = "stack_trace_disclosure"
    EXCEPTION_DISCLOSURE = "exception_disclosure"

    INTERNAL_PATH_DISCLOSURE = "internal_path_disclosure"
    INTERNAL_IP_DISCLOSURE = "internal_ip_disclosure"

    DIRECTORY_LISTING = "directory_listing"
    ERROR_DETAILS_DISCLOSURE = "error_details_disclosure"

    RESPONSE_INFORMATION_PRESENT = "response_information_present"


@dataclass(frozen=True)
class HttpResponseSecurityIndicator:
    type: HttpResponseSecurityIndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class HttpResponseSecurityAnalysis:
    indicators: tuple[HttpResponseSecurityIndicator, ...]

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[HttpResponseSecurityIndicatorType, ...]:
        return tuple(item.type for item in self.indicators)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.indicators)

    def has_type(self, indicator_type: HttpResponseSecurityIndicatorType) -> bool:
        return indicator_type in self.types


class HttpResponseSecurityAnalyzer:
    name = "http_response_security"
    description = "Analyze HTTP responses for information disclosure and unsafe response behavior."

    STACK_TRACE_MARKERS = (
        "traceback",
        "stack trace",
        "stacktrace",
        "at java.",
        "at org.",
        "at com.",
        "exception in thread",
    )

    DEBUG_MARKERS = (
        "debug=true",
        "debug mode",
        "debug toolbar",
        "development mode",
        "development server",
        "debugger",
    )

    INTERNAL_PATH_MARKERS = (
        "/var/www/",
        "/var/log/",
        "/home/",
        "/usr/",
        "/opt/",
        "c:\\inetpub\\",
        "c:\\windows\\",
        "c:\\users\\",
    )

    DIRECTORY_LISTING_MARKERS = (
        "index of /",
        "directory listing",
        "parent directory",
    )

    EXCEPTION_MARKERS = (
        "unhandled exception",
        "uncaught exception",
        "fatal error",
        "runtime error",
        "exception:",
    )

    def analyze(
        self,
        *,
        server: str | None = None,
        x_powered_by: str | None = None,
        body: str | None = None,
        debug: bool = False,
        stack_trace: bool = False,
        exception_details: bool = False,
        internal_path: bool = False,
        internal_ip: bool = False,
        directory_listing: bool = False,
    ) -> HttpResponseSecurityAnalysis:
        indicators: list[HttpResponseSecurityIndicator] = []

        if server:
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.SERVER_DISCLOSURE,
                    "Server header discloses server information",
                    server,
                )
            )

            if any(char.isdigit() for char in server):
                indicators.append(
                    HttpResponseSecurityIndicator(
                        HttpResponseSecurityIndicatorType.SERVER_VERSION_DISCLOSURE,
                        "Server header appears to disclose a version",
                        server,
                    )
                )

        if x_powered_by:
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.X_POWERED_BY,
                    "X-Powered-By header discloses technology information",
                    x_powered_by,
                )
            )
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.TECHNOLOGY_DISCLOSURE,
                    "Technology information is disclosed by the response",
                    x_powered_by,
                )
            )

        content = body or ""
        lowered = content.lower()
        internal_addresses = self._internal_ip_addresses(content)

        if debug or any(marker in lowered for marker in self.DEBUG_MARKERS):
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.DEBUG_DISCLOSURE,
                    "Debug or development information is exposed",
                    body,
                )
            )

        if stack_trace or any(marker in lowered for marker in self.STACK_TRACE_MARKERS):
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.STACK_TRACE_DISCLOSURE,
                    "Stack trace information is exposed",
                    body,
                )
            )

        if exception_details or any(
            marker in lowered for marker in self.EXCEPTION_MARKERS
        ):
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.EXCEPTION_DISCLOSURE,
                    "Exception details are exposed",
                    body,
                )
            )

        if internal_path or any(
            marker in lowered for marker in self.INTERNAL_PATH_MARKERS
        ):
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.INTERNAL_PATH_DISCLOSURE,
                    "Internal filesystem path information is exposed",
                    body,
                )
            )

        if internal_ip and not internal_addresses:
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.INTERNAL_IP_DISCLOSURE,
                    "Internal IP address information is exposed",
                    body,
                )
            )

        for address in internal_addresses:
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.INTERNAL_IP_DISCLOSURE,
                    "Internal IP address information is exposed",
                    address,
                )
            )

        if directory_listing or any(
            marker in lowered for marker in self.DIRECTORY_LISTING_MARKERS
        ):
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.DIRECTORY_LISTING,
                    "Directory listing information is exposed",
                    body,
                )
            )

        if exception_details or debug or stack_trace:
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.ERROR_DETAILS_DISCLOSURE,
                    "Detailed error information is exposed",
                    body,
                )
            )

        if indicators:
            indicators.append(
                HttpResponseSecurityIndicator(
                    HttpResponseSecurityIndicatorType.RESPONSE_INFORMATION_PRESENT,
                    "Security-relevant response information was detected",
                    str(len(indicators)),
                )
            )

        return HttpResponseSecurityAnalysis(tuple(indicators))

    @staticmethod
    def _internal_ip_addresses(content: str) -> tuple[str, ...]:
        """Return distinct private/local IP literals observed in response text."""
        addresses: list[str] = []
        seen: set[str] = set()
        for pattern in (_IPV4_PATTERN, _IPV6_PATTERN):
            for match in pattern.finditer(content):
                value = match.group(0)
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if not any(
                    address.version == network.version and address in network
                    for network in _INTERNAL_NETWORKS
                ):
                    continue
                normalized = str(address)
                if normalized not in seen:
                    seen.add(normalized)
                    addresses.append(value)
        return tuple(addresses)
