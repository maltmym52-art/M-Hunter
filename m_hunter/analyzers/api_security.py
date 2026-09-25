from dataclasses import dataclass, field
from enum import Enum


class APIIndicatorType(str, Enum):
    MISSING_SECURITY_HEADER = "missing_security_header"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    VERBOSE_ERROR = "verbose_error"
    DEBUG_INFORMATION = "debug_information"
    SERVER_DISCLOSURE = "server_disclosure"
    VERSION_DISCLOSURE = "version_disclosure"
    UNRESTRICTED_METHOD = "unrestricted_method"
    MISSING_CONTENT_TYPE = "missing_content_type"
    WEAK_CONTENT_TYPE = "weak_content_type"
    CORS_MISCONFIGURATION = "cors_misconfiguration"


@dataclass(frozen=True)
class APIIndicator:
    type: APIIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass
class APIAnalysis:
    detected: bool = False
    indicator_count: int = 0
    types: list[APIIndicatorType] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    indicators: list[APIIndicator] = field(
        default_factory=list
    )

    @property
    def missing_security_header_detected(self) -> bool:
        return APIIndicatorType.MISSING_SECURITY_HEADER in self.types

    @property
    def excessive_data_exposure_detected(self) -> bool:
        return APIIndicatorType.EXCESSIVE_DATA_EXPOSURE in self.types

    @property
    def verbose_error_detected(self) -> bool:
        return APIIndicatorType.VERBOSE_ERROR in self.types

    @property
    def debug_information_detected(self) -> bool:
        return APIIndicatorType.DEBUG_INFORMATION in self.types

    @property
    def server_disclosure_detected(self) -> bool:
        return APIIndicatorType.SERVER_DISCLOSURE in self.types

    @property
    def version_disclosure_detected(self) -> bool:
        return APIIndicatorType.VERSION_DISCLOSURE in self.types

    @property
    def unrestricted_method_detected(self) -> bool:
        return APIIndicatorType.UNRESTRICTED_METHOD in self.types

    @property
    def missing_content_type_detected(self) -> bool:
        return APIIndicatorType.MISSING_CONTENT_TYPE in self.types

    @property
    def weak_content_type_detected(self) -> bool:
        return APIIndicatorType.WEAK_CONTENT_TYPE in self.types

    @property
    def cors_misconfiguration_detected(self) -> bool:
        return APIIndicatorType.CORS_MISCONFIGURATION in self.types


class APISecurityAnalyzer:
    SECURITY_HEADERS = {
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    }

    DEBUG_MARKERS = {
        "debug",
        "traceback",
        "stack trace",
        "stacktrace",
        "exception",
        "internal server error",
        "development mode",
    }

    SENSITIVE_FIELDS = {
        "password",
        "password_hash",
        "passwordhash",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "private_key",
        "privatekey",
        "credit_card",
        "card_number",
        "ssn",
    }

    WEAK_CONTENT_TYPES = {
        "text/plain",
        "text/html",
        "application/octet-stream",
    }

    def analyze(
        self,
        *,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        allowed_methods: list[str] | None = None,
        expected_methods: list[str] | None = None,
        content_type: str | None = None,
        cors_origin: str | None = None,
        cors_credentials: bool = False,
        required_security_headers: set[str] | None = None,
    ) -> APIAnalysis:
        if headers is not None and not isinstance(headers, dict):
            raise TypeError("headers must be a dictionary")

        if body is not None and not isinstance(body, str):
            raise TypeError("body must be a string")

        if allowed_methods is not None and not isinstance(
            allowed_methods, list
        ):
            raise TypeError("allowed_methods must be a list")

        if expected_methods is not None and not isinstance(
            expected_methods, list
        ):
            raise TypeError("expected_methods must be a list")

        headers = headers or {}
        body = body or ""
        allowed_methods = allowed_methods or []
        expected_methods = expected_methods or []

        if not isinstance(cors_credentials, bool):
            raise TypeError("cors_credentials must be a boolean")

        normalized_headers = {
            str(name).lower(): str(value)
            for name, value in headers.items()
        }

        indicators: list[APIIndicator] = []

        required_headers = (
            required_security_headers
            if required_security_headers is not None
            else self.SECURITY_HEADERS
        )

        for header in required_headers:
            normalized = header.lower()

            if normalized not in normalized_headers:
                indicators.append(
                    APIIndicator(
                        type=APIIndicatorType.MISSING_SECURITY_HEADER,
                        evidence=f"Missing security header: {header}",
                        name=header,
                    )
                )

        body_lower = body.lower()

        for field_name in self.SENSITIVE_FIELDS:
            if field_name.lower() in body_lower:
                indicators.append(
                    APIIndicator(
                        type=APIIndicatorType.EXCESSIVE_DATA_EXPOSURE,
                        evidence=(
                            "Potentially sensitive field exposed "
                            f"in response body: {field_name}"
                        ),
                        name=field_name,
                    )
                )

        for marker in self.DEBUG_MARKERS:
            if marker in body_lower:
                indicators.append(
                    APIIndicator(
                        type=APIIndicatorType.VERBOSE_ERROR,
                        evidence=(
                            "Potential verbose error/debug marker "
                            f"detected: {marker}"
                        ),
                        name=marker,
                    )
                )

        if any(
            marker in body_lower
            for marker in {
                "debug mode",
                "debug=true",
                "development environment",
                "dev environment",
            }
        ):
            indicators.append(
                APIIndicator(
                    type=APIIndicatorType.DEBUG_INFORMATION,
                    evidence=(
                        "Potential development/debug information "
                        "detected in response."
                    ),
                )
            )

        server = normalized_headers.get("server")

        if server:
            indicators.append(
                APIIndicator(
                    type=APIIndicatorType.SERVER_DISCLOSURE,
                    evidence=(
                        f"Server header discloses server information: "
                        f"{server}"
                    ),
                    name="server",
                    value=server,
                )
            )

            if any(char.isdigit() for char in server):
                indicators.append(
                    APIIndicator(
                        type=APIIndicatorType.VERSION_DISCLOSURE,
                        evidence=(
                            f"Potential server version disclosure: "
                            f"{server}"
                        ),
                        name="server",
                        value=server,
                    )
                )

        for method in allowed_methods:
            if method.upper() not in {
                item.upper()
                for item in expected_methods
            }:
                indicators.append(
                    APIIndicator(
                        type=APIIndicatorType.UNRESTRICTED_METHOD,
                        evidence=(
                            f"Method is allowed but not listed as "
                            f"expected: {method.upper()}"
                        ),
                        name=method.upper(),
                    )
                )

        if content_type is None or not content_type.strip():
            indicators.append(
                APIIndicator(
                    type=APIIndicatorType.MISSING_CONTENT_TYPE,
                    evidence="Response content type is missing.",
                )
            )
        else:
            normalized_content_type = (
                content_type.split(";", 1)[0]
                .strip()
                .lower()
            )

            if normalized_content_type in self.WEAK_CONTENT_TYPES:
                indicators.append(
                    APIIndicator(
                        type=APIIndicatorType.WEAK_CONTENT_TYPE,
                        evidence=(
                            "Weak or unexpected API response content "
                            f"type detected: {normalized_content_type}"
                        ),
                        value=normalized_content_type,
                    )
                )

        if cors_origin == "*" and cors_credentials:
            indicators.append(
                APIIndicator(
                    type=APIIndicatorType.CORS_MISCONFIGURATION,
                    evidence=(
                        "Wildcard CORS origin is combined with "
                        "credentials support."
                    ),
                    name="access-control-allow-origin",
                    value="*",
                )
            )

        types = list(
            dict.fromkeys(
                indicator.type
                for indicator in indicators
            )
        )

        names = list(
            dict.fromkeys(
                indicator.name
                for indicator in indicators
                if indicator.name is not None
            )
        )

        return APIAnalysis(
            detected=bool(indicators),
            indicator_count=len(indicators),
            types=types,
            names=names,
            indicators=indicators,
        )
