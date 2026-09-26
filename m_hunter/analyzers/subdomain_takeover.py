from dataclasses import dataclass
from enum import Enum


class SubdomainTakeoverIndicatorType(str, Enum):
    CNAME_PRESENT = "cname_present"
    CNAME_EXTERNAL = "cname_external"
    CNAME_DANGLING = "cname_dangling"
    NXDOMAIN = "nxdomain"
    DNS_ERROR = "dns_error"
    UNRESOLVED_TARGET = "unresolved_target"
    SERVICE_FINGERPRINT = "service_fingerprint"
    TAKEOVER_SIGNATURE = "takeover_signature"
    HOST_NOT_FOUND = "host_not_found"
    RESOURCE_NOT_FOUND = "resource_not_found"
    SERVICE_UNAVAILABLE = "service_unavailable"
    HTTP_404 = "http_404"


@dataclass(frozen=True)
class SubdomainTakeoverIndicator:
    type: SubdomainTakeoverIndicatorType
    name: str
    value: str


@dataclass(frozen=True)
class SubdomainTakeoverAnalysis:
    detected: bool
    indicators: list[SubdomainTakeoverIndicator]

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> list[SubdomainTakeoverIndicatorType]:
        return [i.type for i in self.indicators]

    @property
    def names(self) -> list[str]:
        return [i.name for i in self.indicators]

    def has_type(self, indicator_type: SubdomainTakeoverIndicatorType) -> bool:
        return indicator_type in self.types


class SubdomainTakeoverAnalyzer:
    name = "subdomain_takeover"

    description = (
        "Detects DNS and HTTP indicators associated with potentially "
        "dangling subdomains and third-party service takeover conditions."
    )

    _KNOWN_SERVICE_PATTERNS = (
        "github pages",
        "github.io",
        "herokucdn.com",
        "herokuapp.com",
        "amazonaws.com",
        "cloudfront.net",
        "azurewebsites.net",
        "trafficmanager.net",
        "s3.amazonaws.com",
        "storage.googleapis.com",
        "fastly.net",
        "pantheon.io",
        "readthedocs.io",
        "zendesk.com",
        "shopify.com",
        "tumblr.com",
    )

    _TAKEOVER_SIGNATURES = (
        "there isn't a github pages site here",
        "no such app",
        "no such site",
        "heroku | no such app",
        "the specified bucket does not exist",
        "nosuchbucket",
        "resource not found",
        "project not found",
        "this site is not configured",
        "site not found",
        "domain not found",
        "unknown site",
        "unrecognized domain",
        "the page you are looking for doesn't exist",
    )

    _HOST_NOT_FOUND = (
        "host not found",
        "unknown host",
        "could not resolve host",
        "name or service not known",
    )

    _RESOURCE_NOT_FOUND = (
        "resource not found",
        "not found",
        "does not exist",
    )

    _SERVICE_UNAVAILABLE = (
        "service unavailable",
        "temporarily unavailable",
        "bad gateway",
        "gateway timeout",
    )

    def analyze(
        self,
        *,
        hostname: str,
        cname: str | None = None,
        dns_status: str | None = None,
        resolved: bool | None = None,
        http_status: int | None = None,
        http_headers: dict[str, str] | None = None,
        response_body: str = "",
    ) -> SubdomainTakeoverAnalysis:
        indicators: list[SubdomainTakeoverIndicator] = []
        seen: set[tuple[SubdomainTakeoverIndicatorType, str]] = set()

        def add(
            indicator_type: SubdomainTakeoverIndicatorType,
            name: str,
            value: str,
        ) -> None:
            key = (indicator_type, value)
            if key not in seen:
                seen.add(key)
                indicators.append(
                    SubdomainTakeoverIndicator(
                        type=indicator_type,
                        name=name,
                        value=value,
                    )
                )

        cname_value = (cname or "").strip()

        if cname_value:
            add(
                SubdomainTakeoverIndicatorType.CNAME_PRESENT,
                "CNAME record",
                cname_value,
            )

            hostname_lower = hostname.lower().rstrip(".")
            cname_lower = cname_value.lower().rstrip(".")

            if hostname_lower and cname_lower:
                cname_domain = cname_lower.split(":")[0]

                if not (
                    cname_domain == hostname_lower
                    or cname_domain.endswith("." + hostname_lower)
                ):
                    add(
                        SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
                        "External CNAME target",
                        cname_value,
                    )

        dns_lower = (dns_status or "").lower()

        if "nxdomain" in dns_lower:
            add(
                SubdomainTakeoverIndicatorType.NXDOMAIN,
                "NXDOMAIN response",
                dns_status or "NXDOMAIN",
            )

        if any(
            marker in dns_lower
            for marker in ("servfail", "dns error", "server failure")
        ):
            add(
                SubdomainTakeoverIndicatorType.DNS_ERROR,
                "DNS resolution error",
                dns_status or "DNS error",
            )

        if resolved is False:
            add(
                SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET,
                "Unresolved DNS target",
                hostname,
            )

        combined = " ".join(
            [
                cname_value,
                *(str(v) for v in (http_headers or {}).values()),
                response_body,
            ]
        ).lower()

        for fingerprint in self._KNOWN_SERVICE_PATTERNS:
            if fingerprint in combined:
                add(
                    SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
                    "Third-party service fingerprint",
                    fingerprint,
                )

        body_lower = response_body.lower()

        for signature in self._TAKEOVER_SIGNATURES:
            if signature in body_lower:
                add(
                    SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
                    "Potential takeover service signature",
                    signature,
                )

        for marker in self._HOST_NOT_FOUND:
            if marker in body_lower:
                add(
                    SubdomainTakeoverIndicatorType.HOST_NOT_FOUND,
                    "Host resolution failure",
                    marker,
                )

        for marker in self._RESOURCE_NOT_FOUND:
            if marker in body_lower:
                add(
                    SubdomainTakeoverIndicatorType.RESOURCE_NOT_FOUND,
                    "Missing remote resource",
                    marker,
                )

        for marker in self._SERVICE_UNAVAILABLE:
            if marker in body_lower:
                add(
                    SubdomainTakeoverIndicatorType.SERVICE_UNAVAILABLE,
                    "Service unavailable",
                    marker,
                )

        if http_status == 404:
            add(
                SubdomainTakeoverIndicatorType.HTTP_404,
                "HTTP 404 response",
                "404",
            )

        return SubdomainTakeoverAnalysis(
            detected=bool(indicators),
            indicators=indicators,
        )
