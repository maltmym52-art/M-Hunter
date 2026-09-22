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
