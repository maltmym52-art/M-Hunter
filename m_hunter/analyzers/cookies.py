from dataclasses import dataclass, field


@dataclass(frozen=True)
class CookieSecurity:
    name: str
    value: str
    secure: bool
    httponly: bool
    samesite: str | None
    domain: str | None
    path: str | None
    expires: str | None
    max_age: str | None

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
    def has_secure_transport(self) -> bool:
        return self.secure

    @property
    def protects_from_script_access(self) -> bool:
        return self.httponly

    @property
    def has_samesite_protection(self) -> bool:
        return self.samesite is not None

    @property
    def persistent(self) -> bool:
        return (
            self.expires is not None
            or self.max_age is not None
        )


@dataclass
class CookieAnalysis:
    cookies: list[CookieSecurity] = field(
        default_factory=list
    )

    @property
    def count(self) -> int:
        return len(self.cookies)

    @property
    def session_cookies(self) -> list[CookieSecurity]:
        return [
            cookie
            for cookie in self.cookies
            if cookie.is_session_cookie
        ]

    @property
    def session_count(self) -> int:
        return len(self.session_cookies)

    @property
    def insecure_cookies(self) -> list[CookieSecurity]:
        return [
            cookie
            for cookie in self.cookies
            if not cookie.secure
        ]

    @property
    def httponly_missing(self) -> list[CookieSecurity]:
        return [
            cookie
            for cookie in self.cookies
            if not cookie.httponly
        ]

    @property
    def samesite_missing(self) -> list[CookieSecurity]:
        return [
            cookie
            for cookie in self.cookies
            if cookie.samesite is None
        ]

    def get(self, name: str) -> CookieSecurity | None:
        name = name.strip().lower()

        for cookie in self.cookies:
            if cookie.name.lower() == name:
                return cookie

        return None


class CookieAnalyzer:
    def analyze(
        self,
        cookies: dict[str, str],
    ) -> CookieAnalysis:
        if not isinstance(cookies, dict):
            raise TypeError(
                "cookies must be a dictionary"
            )

        result = CookieAnalysis()

        for name, value in cookies.items():
            if not isinstance(name, str):
                raise TypeError(
                    "cookie names must be strings"
                )

            if not name.strip():
                continue

            result.cookies.append(
                CookieSecurity(
                    name=name.strip(),
                    value=str(value),
                    secure=False,
                    httponly=False,
                    samesite=None,
                    domain=None,
                    path=None,
                    expires=None,
                    max_age=None,
                )
            )

        return result
