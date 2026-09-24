import re
from dataclasses import dataclass, field

from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL


@dataclass(frozen=True)
class JavaScriptURL:
    url: URL
    source: str = "javascript"

    def __post_init__(self):
        if not isinstance(self.url, URL):
            raise TypeError(
                "url must be an instance of URL"
            )

        if not self.source.strip():
            raise ValueError(
                "source must not be empty"
            )

    @property
    def value(self) -> str:
        return str(self.url)


@dataclass
class JavaScriptDiscoveryResult:
    urls: list[JavaScriptURL] = field(
        default_factory=list
    )

    @property
    def count(self) -> int:
        return len(self.urls)

    @property
    def values(self) -> list[str]:
        return [
            item.value
            for item in self.urls
        ]


class JavaScriptEndpointDiscovery:
    ABSOLUTE_PATTERN = re.compile(
        r"""(?P<quote>["'`])(?P<url>(?:https?|wss?)://[^"'`\s<>]+)(?P=quote)""",
        re.IGNORECASE,
    )

    PATH_PATTERN = re.compile(
        r"""(?P<quote>["'`])(?P<path>(?:/|\.\.?/)[A-Za-z0-9_./~:@%+?&=#${}\[\]-]*)(?P=quote)"""
    )

    API_PATTERN = re.compile(
        r"""(?P<quote>["'`])(?P<path>/(?:api|apis|graphql|rest|v[0-9]+)(?:/[A-Za-z0-9_./~:@%+?&=#${}\[\]-]*)?)(?P=quote)""",
        re.IGNORECASE,
    )

    WEBSOCKET_PATTERN = re.compile(
        r"""(?P<quote>["'`])(?P<url>wss?://[^"'`\s<>]+)(?P=quote)""",
        re.IGNORECASE,
    )

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
        javascript: str,
    ) -> JavaScriptDiscoveryResult:
        if not isinstance(base_url, URL):
            raise TypeError(
                "base_url must be an instance of URL"
            )

        if not isinstance(javascript, str):
            raise TypeError(
                "javascript must be a string"
            )

        result = JavaScriptDiscoveryResult()
        seen: set[str] = set()

        candidates = self._extract_candidates(
            javascript
        )

        for candidate in candidates:
            url = self._resolve(
                base_url,
                candidate,
            )

            if url is None:
                continue

            if not self.scope.is_allowed(url):
                continue

            key = url.normalized

            if key in seen:
                continue

            seen.add(key)

            result.urls.append(
                JavaScriptURL(url=url)
            )

        return result

    def _extract_candidates(
        self,
        javascript: str,
    ) -> list[str]:
        candidates: list[str] = []

        for pattern in (
            self.ABSOLUTE_PATTERN,
            self.API_PATTERN,
            self.WEBSOCKET_PATTERN,
            self.PATH_PATTERN,
        ):
            for match in pattern.finditer(
                javascript
            ):
                value = (
                    match.groupdict().get("url")
                    or match.groupdict().get("path")
                )

                if value:
                    candidates.append(
                        value.strip()
                    )

        return candidates

    @staticmethod
    def _resolve(
        base_url: URL,
        candidate: str,
    ) -> URL | None:
        candidate = candidate.strip()

        if not candidate:
            return None

        # Template placeholders are not concrete URLs.
        if "${" in candidate:
            return None

        try:
            # WebSocket URLs are useful discovery
            # targets but are not represented by
            # the HTTP-only URL model.
            if candidate.lower().startswith(
                ("ws://", "wss://")
            ):
                return None

            return base_url.resolve(candidate)

        except (ValueError, TypeError):
            return None
