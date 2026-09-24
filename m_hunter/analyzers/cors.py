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


@dataclass(frozen=True)
class CORSIssue:
    issue: str
    severity: str
    description: str


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
    issues: list[CORSIssue] = field(
        default_factory=list
    )

    @property
    def potentially_sensitive(self) -> bool:
        return bool(self.issues)


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

        issues = self._analyze_issues(
            cors_headers=cors_headers,
            wildcard_origin=wildcard_origin,
            credentials_enabled=credentials_enabled,
            origin_with_credentials=origin_with_credentials,
        )

        return CORSAnalysis(
            headers=cors_headers,
            enabled=bool(headers),
            wildcard_origin=wildcard_origin,
            credentials_enabled=credentials_enabled,
            origin_with_credentials=origin_with_credentials,
            allowed_methods=allowed_methods,
            allowed_headers=allowed_headers,
            issues=issues,
        )

    @staticmethod
    def _analyze_issues(
        cors_headers: CORSHeaders,
        wildcard_origin: bool,
        credentials_enabled: bool,
        origin_with_credentials: bool,
    ) -> list[CORSIssue]:
        issues: list[CORSIssue] = []

        if wildcard_origin and credentials_enabled:
            issues.append(
                CORSIssue(
                    issue="wildcard_origin_with_credentials",
                    severity="high",
                    description=(
                        "CORS allows a wildcard origin while "
                        "credentials are enabled."
                    ),
                )
            )

        if origin_with_credentials:
            issues.append(
                CORSIssue(
                    issue="origin_with_credentials",
                    severity="medium",
                    description=(
                        "CORS allows credentials for a specific "
                        "origin. The origin should be validated "
                        "against an explicit allowlist."
                    ),
                )
            )

        if (
            cors_headers.allow_origin is not None
            and not wildcard_origin
            and cors_headers.allow_origin.strip()
            == "null"
        ):
            issues.append(
                CORSIssue(
                    issue="null_origin_allowed",
                    severity="medium",
                    description=(
                        "CORS explicitly allows the null origin."
                    ),
                )
            )

        if (
            cors_headers.allow_methods is not None
            and "*" in (
                method.strip()
                for method in cors_headers.allow_methods.split(",")
            )
        ):
            issues.append(
                CORSIssue(
                    issue="wildcard_methods",
                    severity="low",
                    description=(
                        "CORS allows all methods through a "
                        "wildcard method value."
                    ),
                )
            )

        if (
            cors_headers.allow_headers is not None
            and "*" in (
                header.strip()
                for header in cors_headers.allow_headers.split(",")
            )
        ):
            issues.append(
                CORSIssue(
                    issue="wildcard_headers",
                    severity="low",
                    description=(
                        "CORS allows all request headers through "
                        "a wildcard header value."
                    ),
                )
            )

        return issues

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
