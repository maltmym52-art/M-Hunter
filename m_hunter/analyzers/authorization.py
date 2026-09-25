from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlparse

from m_hunter.analyzers.http import HTTPAnalysis


@dataclass(frozen=True)
class AuthorizationContext:
    method: str
    url: str
    path: str
    query_parameters: tuple[str, ...] = ()
    has_authorization_header: bool = False
    has_session_cookie: bool = False
    has_body: bool = False


@dataclass
class AuthorizationAnalysis:
    context: AuthorizationContext
    protected_request: bool
    authorization_mechanisms: tuple[str, ...] = field(
        default_factory=tuple
    )
    resource_identifiers: tuple[str, ...] = field(
        default_factory=tuple
    )

    @property
    def has_resource_identifier(self) -> bool:
        return bool(self.resource_identifiers)

    @property
    def authorization_present(self) -> bool:
        return bool(self.authorization_mechanisms)


class AuthorizationAnalyzer:
    RESOURCE_PARAMETER_NAMES = {
        "id",
        "user_id",
        "userid",
        "account_id",
        "accountid",
        "profile_id",
        "profileid",
        "object_id",
        "objectid",
        "resource_id",
        "resourceid",
        "document_id",
        "documentid",
        "file_id",
        "fileid",
        "order_id",
        "orderid",
        "invoice_id",
        "invoiceid",
        "project_id",
        "projectid",
    }

    def analyze(
        self,
        analysis: HTTPAnalysis,
    ) -> AuthorizationAnalysis:
        if not isinstance(
            analysis,
            HTTPAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of HTTPAnalysis"
            )

        request = analysis.request
        parsed_url = urlparse(request.full_url)

        query_parameters = tuple(
            name
            for name, _ in parse_qsl(
                parsed_url.query,
                keep_blank_values=True,
            )
        )

        mechanisms: list[str] = []

        authorization_header = request.get_header(
            "authorization"
        )

        if (
            authorization_header is not None
            and authorization_header.strip()
        ):
            mechanisms.append("authorization_header")

        if request.cookies:
            mechanisms.append("cookie")

        session_cookie_names = {
            "session",
            "sessionid",
            "session_id",
            "sid",
            "jsessionid",
            "phpsessid",
            "asp.net_sessionid",
            "auth",
            "token",
            "access_token",
            "refresh_token",
        }

        has_session_cookie = any(
            name.lower() in session_cookie_names
            for name in request.cookies
        )

        if has_session_cookie:
            mechanisms.append("session_cookie")

        resource_identifiers = self._find_resource_identifiers(
            request.params,
            query_parameters,
        )

        context = AuthorizationContext(
            method=request.method,
            url=request.full_url,
            path=parsed_url.path,
            query_parameters=query_parameters,
            has_authorization_header=(
                authorization_header is not None
                and bool(authorization_header.strip())
            ),
            has_session_cookie=has_session_cookie,
            has_body=request.has_body(),
        )

        return AuthorizationAnalysis(
            context=context,
            protected_request=bool(mechanisms),
            authorization_mechanisms=tuple(
                dict.fromkeys(mechanisms)
            ),
            resource_identifiers=resource_identifiers,
        )

    @classmethod
    def _find_resource_identifiers(
        cls,
        params: dict[str, str],
        query_parameters: tuple[str, ...],
    ) -> tuple[str, ...]:
        identifiers: list[str] = []

        for name in params:
            if name.lower() in cls.RESOURCE_PARAMETER_NAMES:
                identifiers.append(name)

        for name in query_parameters:
            if name.lower() in cls.RESOURCE_PARAMETER_NAMES:
                identifiers.append(name)

        return tuple(dict.fromkeys(identifiers))
