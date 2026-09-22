import json
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
    def get_headers(self) -> dict[str, str]:
        return self.headers.copy()

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
    def get_content_type(self) -> str | None:
        content_type = self.get_header("content-type")

        if content_type is None:
            return None

        return content_type.split(";", 1)[0].strip().lower()
    def is_html(self) -> bool:
        return self.get_content_type() == "text/html"

    def is_json(self) -> bool:
        content_type = self.get_content_type()

        return content_type in {
            "application/json",
            "application/problem+json",
        }

    def json(self):
        if not self.is_json():
            raise ValueError("Response content type is not JSON")

        return json.loads(self.text)


    def get_cookie(self, name: str) -> str | None:
        return self.cookies.get(name)
