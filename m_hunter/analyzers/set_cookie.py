from dataclasses import dataclass


@dataclass(frozen=True)
class SetCookie:
    name: str
    value: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    domain: str | None = None
    path: str | None = None
    expires: str | None = None
    max_age: str | None = None

    @property
    def is_session_cookie(self) -> bool:
        session_names = {
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

        return self.name.lower() in session_names

    @property
    def persistent(self) -> bool:
        return (
            self.expires is not None
            or self.max_age is not None
        )


class SetCookieParser:
    def parse(self, header: str) -> SetCookie:
        if not isinstance(header, str):
            raise TypeError("header must be a string")

        header = header.strip()

        if not header:
            raise ValueError("header must not be empty")

        parts = [
            part.strip()
            for part in header.split(";")
            if part.strip()
        ]

        if not parts or "=" not in parts[0]:
            raise ValueError(
                "invalid Set-Cookie header"
            )

        name, value = parts[0].split("=", 1)

        name = name.strip()
        value = value.strip()

        if not name:
            raise ValueError(
                "cookie name must not be empty"
            )

        attributes = {}

        for part in parts[1:]:
            if "=" in part:
                key, attr_value = part.split("=", 1)
                attributes[
                    key.strip().lower()
                ] = attr_value.strip()
            else:
                attributes[
                    part.strip().lower()
                ] = True

        samesite = attributes.get("samesite")

        if isinstance(samesite, str):
            samesite = samesite.strip().capitalize()

            if samesite not in {
                "Strict",
                "Lax",
                "None",
            }:
                samesite = samesite

        return SetCookie(
            name=name,
            value=value,
            secure="secure" in attributes,
            httponly="httponly" in attributes,
            samesite=samesite,
            domain=attributes.get("domain"),
            path=attributes.get("path"),
            expires=attributes.get("expires"),
            max_age=attributes.get("max-age"),
        )

    def parse_many(
        self,
        headers: list[str],
    ) -> list[SetCookie]:
        if not isinstance(headers, list):
            raise TypeError(
                "headers must be a list"
            )

        cookies = []

        for header in headers:
            cookies.append(
                self.parse(header)
            )

        return cookies
