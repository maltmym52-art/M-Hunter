import re
from dataclasses import dataclass, field

from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL


API_PATH_PATTERN = re.compile(
    r"""
    /
    (?:
        apis
        |api
        |graphql
        |rest
        |v[0-9]+
    )
    (?![A-Za-z0-9_-])
    (?:
        /
        [A-Za-z0-9_./~:@%+?&=#${}\[\]-]*
    )?
    """,
    re.IGNORECASE | re.VERBOSE,
)

GRAPHQL_PATTERN = re.compile(
    r"""
    /
    (?:
        graphql
        |graphiql
    )
    (?:
        /
        [A-Za-z0-9_./~:@%+?&=#${}\[\]-]*
    )?
    """,
    re.IGNORECASE | re.VERBOSE,
)


@dataclass(frozen=True)
class APIEndpoint:
    url: URL
    method: str = "GET"
    source: str = "discovered"
    is_graphql: bool = False
    parameters: tuple[str, ...] = field(
        default_factory=tuple
    )

    def __post_init__(self):
        if not isinstance(self.url, URL):
            raise TypeError(
                "url must be an instance of URL"
            )

        method = self.method.strip().upper()

        if not method:
            raise ValueError(
                "method must not be empty"
            )

        object.__setattr__(
            self,
            "method",
            method,
        )

        normalized_parameters = tuple(
            parameter.strip()
            for parameter in self.parameters
            if parameter.strip()
        )

        object.__setattr__(
            self,
            "parameters",
            normalized_parameters,
        )

        if not self.source.strip():
            raise ValueError(
                "source must not be empty"
            )

    @property
    def parameter_names(self) -> tuple[str, ...]:
        return self.parameters

    @property
    def key(self) -> tuple[
        str,
        str,
        tuple[str, ...],
    ]:
        return (
            self.url.normalized,
            self.method,
            self.parameters,
        )


@dataclass
class APIDiscoveryResult:
    _endpoints: list[APIEndpoint] = field(
        default_factory=list
    )

    @property
    def endpoints(self) -> list[APIEndpoint]:
        return list(self._endpoints)

    @property
    def count(self) -> int:
        return len(self._endpoints)

    @property
    def graphql_endpoints(self) -> list[APIEndpoint]:
        return [
            endpoint
            for endpoint in self._endpoints
            if endpoint.is_graphql
        ]

    @property
    def graphql_count(self) -> int:
        return len(self.graphql_endpoints)

    def add(self, endpoint: APIEndpoint) -> bool:
        if not isinstance(endpoint, APIEndpoint):
            raise TypeError(
                "endpoint must be an instance of APIEndpoint"
            )

        if any(
            existing.key == endpoint.key
            for existing in self.endpoints
        ):
            return False

        self._endpoints.append(endpoint)
        return True


class APIDiscovery:
    def __init__(
        self,
        scope: ScopeManager,
    ):
        if not isinstance(scope, ScopeManager):
            raise TypeError(
                "scope must be an instance of ScopeManager"
            )

        self.scope = scope

    def discover(
        self,
        base_url: URL,
        content: str,
        *,
        source: str = "discovered",
    ) -> APIDiscoveryResult:
        if not isinstance(base_url, URL):
            raise TypeError(
                "base_url must be an instance of URL"
            )

        if not isinstance(content, str):
            raise TypeError(
                "content must be a string"
            )

        if not source.strip():
            raise ValueError(
                "source must not be empty"
            )

        result = APIDiscoveryResult()

        candidates = self._extract_candidates(content)

        for candidate in candidates:
            try:
                url = base_url.resolve(candidate)
            except ValueError:
                continue

            if not self.scope.is_allowed(url):
                continue

            is_graphql = bool(
                GRAPHQL_PATTERN.fullmatch(
                    url.path
                )
            )

            parameters = tuple(
                url.parameter_names
            )

            result.add(
                APIEndpoint(
                    url=url,
                    method="GET",
                    source=source,
                    is_graphql=is_graphql,
                    parameters=parameters,
                )
            )

        return result

    @staticmethod
    def _extract_candidates(
        content: str,
    ) -> list[str]:
        candidates: list[str] = []
        seen: set[str] = set()

        patterns = (
            GRAPHQL_PATTERN,
            API_PATH_PATTERN,
        )

        for pattern in patterns:
            for match in pattern.finditer(content):
                value = match.group(0).strip()

                if not value:
                    continue

                if "${" in value:
                    continue

                if value in seen:
                    continue

                seen.add(value)
                candidates.append(value)

        return candidates
