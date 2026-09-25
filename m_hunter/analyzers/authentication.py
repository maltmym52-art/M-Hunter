from dataclasses import dataclass, field

from m_hunter.analyzers.http import HTTPAnalysis


@dataclass(frozen=True)
class AuthenticationHeaders:
    authorization: str | None = None
    proxy_authorization: str | None = None
    www_authenticate: str | None = None
    proxy_authenticate: str | None = None


@dataclass
class AuthenticationAnalysis:
    headers: AuthenticationHeaders
    has_request_authentication: bool
    has_response_authentication: bool
    authentication_scheme: str | None = None
    challenges: tuple[str, ...] = field(
        default_factory=tuple
    )

    @property
    def authentication_present(self) -> bool:
        return (
            self.has_request_authentication
            or self.has_response_authentication
        )


class AuthenticationAnalyzer:
    def analyze(
        self,
        analysis: HTTPAnalysis,
    ) -> AuthenticationAnalysis:
        if not isinstance(
            analysis,
            HTTPAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of HTTPAnalysis"
            )

        headers = analysis.authentication_headers()

        authentication_headers = AuthenticationHeaders(
            authorization=headers.get("authorization"),
            proxy_authorization=headers.get(
                "proxy-authorization"
            ),
            www_authenticate=headers.get(
                "www-authenticate"
            ),
            proxy_authenticate=headers.get(
                "proxy-authenticate"
            ),
        )

        has_request_authentication = any(
            value is not None and value.strip()
            for value in (
                authentication_headers.authorization,
                authentication_headers.proxy_authorization,
            )
        )

        has_response_authentication = any(
            value is not None and value.strip()
            for value in (
                authentication_headers.www_authenticate,
                authentication_headers.proxy_authenticate,
            )
        )

        challenges = self._parse_challenges(
            authentication_headers.www_authenticate
        )

        authentication_scheme = self._extract_scheme(
            authentication_headers.authorization
        )

        return AuthenticationAnalysis(
            headers=authentication_headers,
            has_request_authentication=(
                has_request_authentication
            ),
            has_response_authentication=(
                has_response_authentication
            ),
            authentication_scheme=authentication_scheme,
            challenges=challenges,
        )

    @staticmethod
    def _extract_scheme(
        authorization: str | None,
    ) -> str | None:
        if not authorization:
            return None

        value = authorization.strip()

        if not value:
            return None

        return value.split(None, 1)[0]

    @staticmethod
    def _parse_challenges(
        www_authenticate: str | None,
    ) -> tuple[str, ...]:
        if not www_authenticate:
            return ()

        challenges = []

        for challenge in www_authenticate.split(","):
            challenge = challenge.strip()

            if not challenge:
                continue

            scheme = challenge.split(None, 1)[0]

            if scheme not in challenges:
                challenges.append(scheme)

        return tuple(challenges)
