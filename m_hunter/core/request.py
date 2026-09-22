from dataclasses import dataclass, field
from urllib.parse import urlencode


@dataclass
class HttpRequest:
    method: str
    url: str

    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: object | None = None

    def __post_init__(self):
        self.method = self.method.upper()

        if not self.method.strip():
            raise ValueError("method must not be empty")

        if not self.url.strip():
            raise ValueError("url must not be empty")

    @property
    def query_string(self) -> str:
        return urlencode(self.params)

    @property
    def full_url(self) -> str:
        if not self.params:
            return self.url

        separator = "&" if "?" in self.url else "?"

        return f"{self.url}{separator}{self.query_string}"

    def get_header(self, name: str) -> str | None:
        name = name.lower()

        return next(
            (
                value
                for header_name, value in self.headers.items()
                if header_name.lower() == name
            ),
            None,
        )

    def get_cookie(self, name: str) -> str | None:
        return self.cookies.get(name)

    def has_body(self) -> bool:
        return self.body is not None

    def copy(self) -> "HttpRequest":
        return HttpRequest(
            method=self.method,
            url=self.url,
            headers=self.headers.copy(),
            cookies=self.cookies.copy(),
            params=self.params.copy(),
            body=self.body,
        )
