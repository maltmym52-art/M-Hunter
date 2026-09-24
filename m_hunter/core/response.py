import json
from dataclasses import dataclass, field


@dataclass
class HttpResponse:
    status_code: int
    url: str
    headers: dict[str, str]
    content: bytes
    cookies: dict[str, str]
    response_time: float
    content_length: int
    repeated_headers: dict[str, list[str]] = field(
        default_factory=dict
    )

    @property
    def status_category(self) -> str:
        if self.is_success:
            return "success"

        if self.is_redirect:
            return "redirect"

        if self.is_client_error:
            return "client_error"

        if self.is_server_error:
            return "server_error"

        return "informational"

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

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

    def get_headers_all(
        self,
        name: str,
    ) -> list[str]:
        name = name.lower()

        values = [
            value
            for header_name, value in self.headers.items()
            if header_name.lower() == name
        ]

        for header_name, repeated_values in (
            self.repeated_headers.items()
        ):
            if header_name.lower() == name:
                values.extend(repeated_values)

        return values

    def get_cookie(self, name: str) -> str | None:
        return self.cookies.get(name)

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

    def is_text(self) -> bool:
        content_type = self.get_content_type()

        if content_type is None:
            return False

        return (
            content_type.startswith("text/")
            or content_type in {
                "application/json",
                "application/javascript",
                "application/xml",
                "application/xhtml+xml",
            }
        )
