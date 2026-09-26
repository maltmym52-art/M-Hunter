from dataclasses import dataclass
from enum import Enum


class SessionIndicatorType(str, Enum):
    SESSION_COOKIE = "session_cookie"
    SESSION_ID_IN_URL = "session_id_in_url"
    SESSION_TOKEN = "session_token"
    SESSION_FIXATION_INDICATOR = "session_fixation_indicator"
    SESSION_ROTATION = "session_rotation"
    SESSION_TIMEOUT = "session_timeout"
    SESSION_LOGOUT = "session_logout"
    SESSION_INVALIDATION = "session_invalidation"
    LONG_LIVED_SESSION = "long_lived_session"
    CONCURRENT_SESSION = "concurrent_session"
    TOKEN_EXPOSURE = "token_exposure"
    WEAK_SESSION_COOKIE_NAME = "weak_session_cookie_name"


@dataclass(frozen=True)
class SessionIndicator:
    type: SessionIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class SessionAnalysis:
    indicators: tuple[SessionIndicator, ...]

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> set[SessionIndicatorType]:
        return {indicator.type for indicator in self.indicators}

    @property
    def names(self) -> set[str]:
        return {
            indicator.name
            for indicator in self.indicators
            if indicator.name is not None
        }

    @property
    def session_cookie(self) -> bool:
        return SessionIndicatorType.SESSION_COOKIE in self.types

    @property
    def session_id_in_url(self) -> bool:
        return SessionIndicatorType.SESSION_ID_IN_URL in self.types

    @property
    def session_token(self) -> bool:
        return SessionIndicatorType.SESSION_TOKEN in self.types

    @property
    def fixation_indicator(self) -> bool:
        return SessionIndicatorType.SESSION_FIXATION_INDICATOR in self.types

    @property
    def rotation(self) -> bool:
        return SessionIndicatorType.SESSION_ROTATION in self.types

    @property
    def timeout(self) -> bool:
        return SessionIndicatorType.SESSION_TIMEOUT in self.types

    @property
    def logout(self) -> bool:
        return SessionIndicatorType.SESSION_LOGOUT in self.types

    @property
    def invalidation(self) -> bool:
        return SessionIndicatorType.SESSION_INVALIDATION in self.types

    @property
    def long_lived_session(self) -> bool:
        return SessionIndicatorType.LONG_LIVED_SESSION in self.types

    @property
    def concurrent_session(self) -> bool:
        return SessionIndicatorType.CONCURRENT_SESSION in self.types

    @property
    def token_exposure(self) -> bool:
        return SessionIndicatorType.TOKEN_EXPOSURE in self.types

    @property
    def weak_session_cookie_name(self) -> bool:
        return SessionIndicatorType.WEAK_SESSION_COOKIE_NAME in self.types


class SessionAnalyzer:
    SESSION_COOKIE_NAMES = {
        "session",
        "sessionid",
        "session_id",
        "sid",
        "jsessionid",
        "phpsessid",
        "connect.sid",
        "auth",
        "auth_token",
        "access_token",
        "refresh_token",
    }

    SESSION_URL_MARKERS = {
        "session",
        "sessionid",
        "session_id",
        "sid",
        "jsessionid",
        "phpsessid",
        "token",
        "auth",
        "auth_token",
        "access_token",
        "refresh_token",
    }

    SESSION_COOKIE_MARKERS = {
        "session",
        "sessionid",
        "session_id",
        "sid",
        "jsessionid",
        "phpsessid",
        "connect.sid",
        "auth",
        "auth_token",
        "access_token",
        "refresh_token",
    }

    def analyze(
        self,
        *,
        url: str | None = None,
        params: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        session_cookie: bool | None = None,
        session_token: bool | None = None,
        fixation_indicator: bool | None = None,
        rotation: bool | None = None,
        timeout: bool | None = None,
        logout: bool | None = None,
        invalidation: bool | None = None,
        long_lived: bool | None = None,
        concurrent: bool | None = None,
        token_exposure: bool | None = None,
        weak_cookie_name: bool | None = None,
    ) -> SessionAnalysis:
        indicators: list[SessionIndicator] = []

        url_value = (url or "").strip()
        params = params or {}
        cookies = cookies or {}
        headers = headers or {}

        def add(
            indicator_type: SessionIndicatorType,
            evidence: str,
            name: str | None = None,
            value: str | None = None,
        ) -> None:
            indicators.append(
                SessionIndicator(
                    type=indicator_type,
                    evidence=evidence,
                    name=name,
                    value=value,
                )
            )

        # Explicit indicators.
        explicit = {
            SessionIndicatorType.SESSION_COOKIE: session_cookie,
            SessionIndicatorType.SESSION_TOKEN: session_token,
            SessionIndicatorType.SESSION_FIXATION_INDICATOR: fixation_indicator,
            SessionIndicatorType.SESSION_ROTATION: rotation,
            SessionIndicatorType.SESSION_TIMEOUT: timeout,
            SessionIndicatorType.SESSION_LOGOUT: logout,
            SessionIndicatorType.SESSION_INVALIDATION: invalidation,
            SessionIndicatorType.LONG_LIVED_SESSION: long_lived,
            SessionIndicatorType.CONCURRENT_SESSION: concurrent,
            SessionIndicatorType.TOKEN_EXPOSURE: token_exposure,
            SessionIndicatorType.WEAK_SESSION_COOKIE_NAME: weak_cookie_name,
        }

        for indicator_type, enabled in explicit.items():
            if enabled is True:
                add(
                    indicator_type,
                    f"Explicit session indicator: {indicator_type.value}",
                )

        # Session cookies.
        for name, value in cookies.items():
            lower_name = name.lower()
            if lower_name in self.SESSION_COOKIE_MARKERS or any(
                marker in lower_name for marker in self.SESSION_COOKIE_MARKERS
            ):
                add(
                    SessionIndicatorType.SESSION_COOKIE,
                    f"Session-related cookie detected: {name}",
                    name=name,
                    value=value,
                )

                if lower_name in {"sid", "session", "auth"}:
                    add(
                        SessionIndicatorType.WEAK_SESSION_COOKIE_NAME,
                        f"Generic session cookie name detected: {name}",
                        name=name,
                        value=value,
                    )

        # Set-Cookie response headers.
        for header_name, header_value in headers.items():
            if header_name.lower() == "set-cookie":
                lower_value = header_value.lower()
                cookie_name = header_value.split("=", 1)[0].strip()

                if any(
                    marker in cookie_name.lower()
                    for marker in self.SESSION_COOKIE_MARKERS
                ):
                    add(
                        SessionIndicatorType.SESSION_COOKIE,
                        f"Session-related Set-Cookie header detected: {cookie_name}",
                        name=cookie_name,
                        value=header_value,
                    )

                if "max-age=" in lower_value or "expires=" in lower_value:
                    add(
                        SessionIndicatorType.LONG_LIVED_SESSION,
                        f"Session cookie lifetime attribute detected: {cookie_name}",
                        name=cookie_name,
                        value=header_value,
                    )

        # Session-related parameters.
        for name, value in params.items():
            lower_name = name.lower()

            if lower_name in self.SESSION_URL_MARKERS or any(
                marker in lower_name for marker in self.SESSION_URL_MARKERS
            ):
                add(
                    SessionIndicatorType.SESSION_TOKEN,
                    f"Session-related parameter detected: {name}",
                    name=name,
                    value=value,
                )

                if lower_name in {"sid", "sessionid", "session_id", "jsessionid"}:
                    add(
                        SessionIndicatorType.SESSION_ID_IN_URL,
                        f"Session identifier parameter detected: {name}",
                        name=name,
                        value=value,
                    )

                if "token" in lower_name or "auth" in lower_name:
                    add(
                        SessionIndicatorType.TOKEN_EXPOSURE,
                        f"Session/auth token parameter detected: {name}",
                        name=name,
                        value=value,
                    )

        # Session identifiers in URL query/fragment/path.
        lower_url = url_value.lower()
        if lower_url:
            if any(
                f"{marker}=" in lower_url
                or f"/{marker}/" in lower_url
                or f"/{marker}=" in lower_url
                for marker in self.SESSION_URL_MARKERS
            ):
                add(
                    SessionIndicatorType.SESSION_ID_IN_URL,
                    "Session-related identifier appears in the URL.",
                    value=url_value,
                )

            if any(
                marker in lower_url
                for marker in ("access_token=", "refresh_token=", "auth_token=")
            ):
                add(
                    SessionIndicatorType.TOKEN_EXPOSURE,
                    "Authentication/session token appears in the URL.",
                    value=url_value,
                )

        # Header-based token indicators.
        for name, value in headers.items():
            lower_name = name.lower()
            lower_value = value.lower()

            if lower_name in {"authorization", "proxy-authorization"}:
                if lower_value.startswith(("bearer ", "basic ", "token ")):
                    add(
                        SessionIndicatorType.SESSION_TOKEN,
                        f"Authentication token carried in {name} header.",
                        name=name,
                        value=value,
                    )

        # Deduplicate exact indicators.
        unique: list[SessionIndicator] = []
        seen: set[tuple] = set()

        for indicator in indicators:
            key = (
                indicator.type,
                indicator.evidence,
                indicator.name,
                indicator.value,
            )
            if key not in seen:
                seen.add(key)
                unique.append(indicator)

        return SessionAnalysis(indicators=tuple(unique))
