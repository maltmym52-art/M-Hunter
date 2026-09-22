from dataclasses import dataclass


@dataclass
class HttpResponse:
    status_code: int
    url: str
    headers: dict[str, str]
    content: bytes
    cookies: dict[str, str]
    response_time: float
    content_length: int

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

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
