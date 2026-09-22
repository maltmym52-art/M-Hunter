from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Target:
    url: str

    @property
    def scheme(self) -> str:
        return urlparse(self.url).scheme

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    @property
    def port(self) -> int | None:
        return urlparse(self.url).port

    @property
    def base_url(self) -> str:
        parsed = urlparse(self.url)

        scheme = parsed.scheme
        host = parsed.hostname

        if not scheme or not host:
            return self.url

        if parsed.port:
            return f"{scheme}://{host}:{parsed.port}"

        return f"{scheme}://{host}"
