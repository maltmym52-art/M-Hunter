from dataclasses import dataclass, field

from m_hunter.analyzers.http import HTTPAnalysis


@dataclass(frozen=True)
class CORSHeaders:
    allow_origin: str | None = None
    allow_credentials: str | None = None
    allow_methods: str | None = None
    allow_headers: str | None = None
    expose_headers: str | None = None
    max_age: str | None = None


@dataclass
class CORSAnalysis:
    headers: CORSHeaders
    enabled: bool
    wildcard_origin: bool
    credentials_enabled: bool
    origin_with_credentials: bool
    allowed_methods: tuple[str, ...] = field(
        default_factory=tuple
    )
    allowed_headers: tuple[str, ...] = field(
        default_factory=tuple
    )

    @property
    def potentially_sensitive(self) -> bool:
        return (
            self.origin_with_credentials
            or (
                self.wildcard_origin
                and self.credentials_enabled
            )
        )


class CORSAnalyzer:
    def analyze(
        self,
        analysis: HTTPAnalysis,
    ) -> CORSAnalysis:
        if not isinstance(
            analysis,
            HTTPAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of HTTPAnalysis"
            )

        headers = analysis.cors_headers()

        cors_headers = CORSHeaders(
            allow_origin=headers.get(
                "access-control-allow-origin"
            ),
            allow_credentials=headers.get(
                "access-control-allow-credentials"
            ),
            allow_methods=headers.get(
                "access-control-allow-methods"
            ),
            allow_headers=headers.get(
                "access-control-allow-headers"
            ),
            expose_headers=headers.get(
                "access-control-expose-headers"
            ),
            max_age=headers.get(
                "access-control-max-age"
            ),
        )

        allow_origin = cors_headers.allow_origin
        allow_credentials = (
            cors_headers.allow_credentials
        )

        wildcard_origin = (
            allow_origin is not None
            and allow_origin.strip() == "*"
        )

        credentials_enabled = (
            allow_credentials is not None
            and allow_credentials.strip().lower()
            == "true"
        )

        origin_with_credentials = (
            allow_origin is not None
            and not wildcard_origin
            and credentials_enabled
        )

        allowed_methods = self._split_values(
            cors_headers.allow_methods
        )

        allowed_headers = self._split_values(
            cors_headers.allow_headers
        )

        return CORSAnalysis(
            headers=cors_headers,
            enabled=bool(headers),
            wildcard_origin=wildcard_origin,
            credentials_enabled=credentials_enabled,
            origin_with_credentials=origin_with_credentials,
            allowed_methods=allowed_methods,
            allowed_headers=allowed_headers,
        )

    @staticmethod
    def _split_values(
        value: str | None,
    ) -> tuple[str, ...]:
        if value is None:
            return ()

        return tuple(
            item.strip()
            for item in value.split(",")
            if item.strip()
        )
