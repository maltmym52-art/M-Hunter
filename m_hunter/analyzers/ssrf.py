from dataclasses import dataclass, field
import re
from urllib.parse import urlparse

from m_hunter.core.response import HttpResponse


class SSRFIndicatorType:
    INTERNAL_IP = "internal_ip"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    INTERNAL_HOSTNAME = "internal_hostname"
    CLOUD_METADATA = "cloud_metadata"
    LOCAL_FILE = "local_file"


@dataclass(frozen=True)
class SSRFIndicator:
    type: str
    evidence: str
    position: int


@dataclass
class SSRFAnalysis:
    indicators: list[SSRFIndicator] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def indicator_count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                indicator.type
                for indicator in self.indicators
            )
        )


class SSRFAnalyzer:
    """
    Detects SSRF-related indicators in an HTTP response.

    Indicators are evidence for further validation. Detection alone
    does not prove that the server performed an SSRF request.
    """

    INTERNAL_PATTERNS = (
        r"\b127(?:\.\d{1,3}){3}\b",
        r"\b10(?:\.\d{1,3}){3}\b",
        r"\b192\.168(?:\.\d{1,3}){2}\b",
        r"\b172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}\b",
        r"\b169\.254(?:\.\d{1,3}){2}\b",
    )

    INTERNAL_HOSTNAMES = (
        r"\blocalhost\b",
        r"\blocalhost\.localdomain\b",
        r"\binternal\b",
        r"\bintranet\b",
    )

    CLOUD_METADATA_PATTERNS = (
        r"169\.254\.169\.254",
        r"metadata\.google\.internal",
        r"metadata\.googleapis\.com",
        r"instance-data",
        r"latest/meta-data",
        r"computeMetadata",
    )

    LOCAL_FILE_PATTERNS = (
        r"file:///",
        r"file:\s*///",
    )

    def analyze(self, response: HttpResponse) -> SSRFAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an HttpResponse"
            )

        content = response.text
        indicators: list[SSRFIndicator] = []

        self._collect(
            content,
            self.INTERNAL_PATTERNS,
            SSRFIndicatorType.INTERNAL_IP,
            indicators,
        )

        self._collect(
            content,
            self.INTERNAL_HOSTNAMES,
            SSRFIndicatorType.INTERNAL_HOSTNAME,
            indicators,
        )

        self._collect(
            content,
            self.CLOUD_METADATA_PATTERNS,
            SSRFIndicatorType.CLOUD_METADATA,
            indicators,
        )

        self._collect(
            content,
            self.LOCAL_FILE_PATTERNS,
            SSRFIndicatorType.LOCAL_FILE,
            indicators,
        )

        return SSRFAnalysis(indicators=indicators)

    @staticmethod
    def _collect(
        content: str,
        patterns: tuple[str, ...],
        indicator_type: str,
        indicators: list[SSRFIndicator],
    ) -> None:
        for pattern in patterns:
            for match in re.finditer(
                pattern,
                content,
                re.IGNORECASE,
            ):
                indicators.append(
                    SSRFIndicator(
                        type=indicator_type,
                        evidence=match.group(0),
                        position=match.start(),
                    )
                )
