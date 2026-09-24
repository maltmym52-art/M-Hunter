from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse


@dataclass(frozen=True)
class URL:
    value: str

    def __post_init__(self):
        normalized = self.value.strip()

        if not normalized:
            raise ValueError(
                "url must not be empty"
            )

        parsed = urlparse(normalized)

        if parsed.scheme.lower() not in {
            "http",
            "https",
        }:
            raise ValueError(
                "url must use http or https"
            )

        if not parsed.netloc:
            raise ValueError(
                "url must include a host"
            )

        object.__setattr__(
            self,
            "value",
            normalized,
        )

    @property
    def scheme(self) -> str:
        return urlparse(self.value).scheme.lower()

    @property
    def host(self) -> str:
        return urlparse(self.value).hostname or ""

    @property
    def port(self) -> int | None:
        return urlparse(self.value).port

    @property
    def path(self) -> str:
        return urlparse(self.value).path or "/"

    @property
    def query(self) -> str:
        return urlparse(self.value).query

    @property
    def fragment(self) -> str:
        return urlparse(self.value).fragment

    @property
    def parameters(self) -> dict[str, str]:
        return dict(
            parse_qsl(
                self.query,
                keep_blank_values=True,
            )
        )

    @property
    def parameter_names(self) -> tuple[str, ...]:
        return tuple(
            name
            for name, _ in parse_qsl(
                self.query,
                keep_blank_values=True,
            )
        )

    @property
    def origin(self) -> str:
        parsed = urlparse(self.value)

        host = parsed.hostname or ""

        if parsed.port is not None:
            return f"{parsed.scheme.lower()}://{host}:{parsed.port}"

        return f"{parsed.scheme.lower()}://{host}"

    @property
    def normalized(self) -> str:
        parsed = urlparse(self.value)

        query = urlencode(
            parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )
        )

        return parsed._replace(
            scheme=parsed.scheme.lower(),
            fragment="",
            query=query,
        ).geturl()

    def without_query(self) -> str:
        parsed = urlparse(self.value)

        return parsed._replace(
            query="",
            fragment="",
        ).geturl()

    def without_fragment(self) -> str:
        parsed = urlparse(self.value)

        return parsed._replace(
            fragment="",
        ).geturl()

    def resolve(self, relative_url: str) -> "URL":
        resolved = urljoin(
            self.value,
            relative_url.strip(),
        )

        return URL(resolved)

    def is_same_origin(self, other: "URL") -> bool:
        return self.origin == other.origin

    def __str__(self) -> str:
        return self.value
