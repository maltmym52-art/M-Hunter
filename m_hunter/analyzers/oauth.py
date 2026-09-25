from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import parse_qs, urlparse


class OAuthIndicatorType(str, Enum):
    REDIRECT_URI = "redirect_uri"
    STATE_PARAMETER = "state_parameter"
    NONCE_PARAMETER = "nonce_parameter"
    RESPONSE_TYPE = "response_type"
    GRANT_TYPE = "grant_type"
    CLIENT_ID = "client_id"
    SCOPE = "scope"
    TOKEN_IN_URL = "token_in_url"
    OPEN_REDIRECT_INDICATOR = "open_redirect_indicator"
    WEAK_STATE_INDICATOR = "weak_state_indicator"
    MISSING_NONCE_INDICATOR = "missing_nonce_indicator"


@dataclass(frozen=True)
class OAuthIndicator:
    type: OAuthIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class OAuthAnalysis:
    detected: bool
    count: int
    types: tuple[OAuthIndicatorType, ...]
    names: tuple[str, ...]
    indicators: tuple[OAuthIndicator, ...]

    @property
    def has_redirect_uri(self) -> bool:
        return OAuthIndicatorType.REDIRECT_URI in self.types

    @property
    def has_state(self) -> bool:
        return OAuthIndicatorType.STATE_PARAMETER in self.types

    @property
    def has_nonce(self) -> bool:
        return OAuthIndicatorType.NONCE_PARAMETER in self.types

    @property
    def has_response_type(self) -> bool:
        return OAuthIndicatorType.RESPONSE_TYPE in self.types

    @property
    def has_grant_type(self) -> bool:
        return OAuthIndicatorType.GRANT_TYPE in self.types

    @property
    def has_client_id(self) -> bool:
        return OAuthIndicatorType.CLIENT_ID in self.types

    @property
    def has_scope(self) -> bool:
        return OAuthIndicatorType.SCOPE in self.types

    @property
    def has_token_in_url(self) -> bool:
        return OAuthIndicatorType.TOKEN_IN_URL in self.types

    @property
    def has_open_redirect_indicator(self) -> bool:
        return OAuthIndicatorType.OPEN_REDIRECT_INDICATOR in self.types

    @property
    def has_weak_state_indicator(self) -> bool:
        return OAuthIndicatorType.WEAK_STATE_INDICATOR in self.types

    @property
    def has_missing_nonce_indicator(self) -> bool:
        return OAuthIndicatorType.MISSING_NONCE_INDICATOR in self.types


class OAuthAnalyzer:
    """Analyzes OAuth request/response indicators without exploitation."""

    OAUTH_PATH_MARKERS = (
        "/oauth",
        "/authorize",
        "/authorization",
        "/oauth2",
        "/auth",
        "/token",
    )

    TOKEN_KEYS = {
        "access_token",
        "id_token",
        "refresh_token",
        "token",
    }

    def analyze(
        self,
        url: str | None = None,
        *,
        params: dict[str, Any] | None = None,
        fragment: str | None = None,
        headers: dict[str, str] | None = None,
        response_type: str | None = None,
        grant_type: str | None = None,
        client_id: str | None = None,
        scope: str | None = None,
        state: str | None = None,
        nonce: str | None = None,
        expected_nonce: bool = False,
        redirect_uri: str | None = None,
    ) -> OAuthAnalysis:
        if url is not None and not isinstance(url, str):
            raise TypeError("url must be a string or None")

        if params is not None and not isinstance(params, dict):
            raise TypeError("params must be a dictionary or None")

        if fragment is not None and not isinstance(fragment, str):
            raise TypeError("fragment must be a string or None")

        if headers is not None and not isinstance(headers, dict):
            raise TypeError("headers must be a dictionary or None")

        params = params.copy() if params else {}
        headers = headers.copy() if headers else {}

        indicators: list[OAuthIndicator] = []

        def add(
            indicator_type: OAuthIndicatorType,
            evidence: str,
            name: str | None = None,
            value: str | None = None,
        ) -> None:
            indicators.append(
                OAuthIndicator(
                    type=indicator_type,
                    evidence=evidence,
                    name=name,
                    value=value,
                )
            )

        parsed_url = urlparse(url) if url else None

        if parsed_url:
            query_params = parse_qs(
                parsed_url.query,
                keep_blank_values=True,
            )
            for key, values in query_params.items():
                if key not in params:
                    params[key] = values[-1] if values else ""

            if parsed_url.fragment and fragment is None:
                fragment = parsed_url.fragment

            path = parsed_url.path.lower()
            if any(marker in path for marker in self.OAUTH_PATH_MARKERS):
                add(
                    OAuthIndicatorType.REDIRECT_URI,
                    f"OAuth-related endpoint detected in URL path: {parsed_url.path}",
                    name="url",
                    value=parsed_url.path,
                )

        normalized = {
            str(key).lower(): str(value)
            for key, value in params.items()
        }

        effective_response_type = (
            response_type
            or normalized.get("response_type")
        )
        effective_grant_type = (
            grant_type
            or normalized.get("grant_type")
        )
        effective_client_id = (
            client_id
            or normalized.get("client_id")
        )
        effective_scope = (
            scope
            or normalized.get("scope")
        )
        effective_state = (
            state
            if state is not None
            else normalized.get("state")
        )
        effective_nonce = (
            nonce
            if nonce is not None
            else normalized.get("nonce")
        )
        effective_redirect_uri = (
            redirect_uri
            or normalized.get("redirect_uri")
        )

        if effective_redirect_uri is not None:
            add(
                OAuthIndicatorType.REDIRECT_URI,
                "OAuth redirect_uri parameter detected.",
                name="redirect_uri",
                value=effective_redirect_uri,
            )

            parsed_redirect = urlparse(effective_redirect_uri)
            if (
                parsed_redirect.scheme
                and parsed_redirect.netloc
                and (
                    parsed_redirect.username
                    or "@" in parsed_redirect.netloc
                )
            ):
                add(
                    OAuthIndicatorType.OPEN_REDIRECT_INDICATOR,
                    "Redirect URI contains a userinfo component that requires validation.",
                    name="redirect_uri",
                    value=effective_redirect_uri,
                )

        if effective_state is not None:
            add(
                OAuthIndicatorType.STATE_PARAMETER,
                "OAuth state parameter detected.",
                name="state",
                value=effective_state,
            )

            if len(effective_state) < 8:
                add(
                    OAuthIndicatorType.WEAK_STATE_INDICATOR,
                    "OAuth state value is unusually short and requires validation.",
                    name="state",
                    value=effective_state,
                )

        if effective_nonce is not None:
            add(
                OAuthIndicatorType.NONCE_PARAMETER,
                "OAuth nonce parameter detected.",
                name="nonce",
                value=effective_nonce,
            )

        if expected_nonce and effective_nonce is None:
            add(
                OAuthIndicatorType.MISSING_NONCE_INDICATOR,
                "A nonce was expected but was not observed.",
                name="nonce",
            )

        if effective_response_type is not None:
            add(
                OAuthIndicatorType.RESPONSE_TYPE,
                "OAuth response_type parameter detected.",
                name="response_type",
                value=effective_response_type,
            )

        if effective_grant_type is not None:
            add(
                OAuthIndicatorType.GRANT_TYPE,
                "OAuth grant_type parameter detected.",
                name="grant_type",
                value=effective_grant_type,
            )

        if effective_client_id is not None:
            add(
                OAuthIndicatorType.CLIENT_ID,
                "OAuth client_id parameter detected.",
                name="client_id",
                value=effective_client_id,
            )

        if effective_scope is not None:
            add(
                OAuthIndicatorType.SCOPE,
                "OAuth scope parameter detected.",
                name="scope",
                value=effective_scope,
            )

        all_url_data = " ".join(
            part
            for part in (
                parsed_url.query if parsed_url else "",
                fragment or "",
            )
            if part
        ).lower()

        for token_key in self.TOKEN_KEYS:
            if token_key in normalized or token_key in all_url_data:
                add(
                    OAuthIndicatorType.TOKEN_IN_URL,
                    f"OAuth token-like value detected in URL data: {token_key}.",
                    name=token_key,
                )

        if (
            effective_response_type
            and "token" in effective_response_type.lower()
        ):
            add(
                OAuthIndicatorType.TOKEN_IN_URL,
                "OAuth response_type includes a token value.",
                name="response_type",
                value=effective_response_type,
            )

        if (
            effective_redirect_uri
            and (
                effective_redirect_uri.startswith("http://")
                or effective_redirect_uri.startswith("//")
            )
        ):
            add(
                OAuthIndicatorType.OPEN_REDIRECT_INDICATOR,
                "Redirect URI uses a form that requires strict allowlist validation.",
                name="redirect_uri",
                value=effective_redirect_uri,
            )

        unique_types: list[OAuthIndicatorType] = []
        for indicator in indicators:
            if indicator.type not in unique_types:
                unique_types.append(indicator.type)

        unique_names: list[str] = []
        for indicator in indicators:
            if indicator.name and indicator.name not in unique_names:
                unique_names.append(indicator.name)

        return OAuthAnalysis(
            detected=bool(indicators),
            count=len(indicators),
            types=tuple(unique_types),
            names=tuple(unique_names),
            indicators=tuple(indicators),
        )
