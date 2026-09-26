from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import parse_qsl, urlparse


class IDORIndicatorType(str, Enum):
    RESOURCE_PARAMETER = "resource_parameter"
    RESOURCE_PATH = "resource_path"
    USER_IDENTIFIER = "user_identifier"
    ACCOUNT_IDENTIFIER = "account_identifier"
    OBJECT_IDENTIFIER = "object_identifier"
    DOCUMENT_IDENTIFIER = "document_identifier"
    FILE_IDENTIFIER = "file_identifier"
    ORDER_IDENTIFIER = "order_identifier"
    INVOICE_IDENTIFIER = "invoice_identifier"
    PROJECT_IDENTIFIER = "project_identifier"
    AUTHENTICATION_CONTEXT = "authentication_context"
    SESSION_CONTEXT = "session_context"
    API_RESOURCE = "api_resource"
    NUMERIC_IDENTIFIER = "numeric_identifier"
    UUID_IDENTIFIER = "uuid_identifier"


@dataclass(frozen=True)
class IDORIndicator:
    type: IDORIndicatorType
    name: str
    value: str | None = None


@dataclass
class IDORAnalysis:
    detected: bool
    indicators: list[IDORIndicator] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[IDORIndicatorType, ...]:
        return tuple(
            dict.fromkeys(
                indicator.type
                for indicator in self.indicators
            )
        )

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                indicator.name
                for indicator in self.indicators
            )
        )

    def has_type(
        self,
        indicator_type: IDORIndicatorType,
    ) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class IDORAnalyzer:
    RESOURCE_PARAMETER_TYPES = {
        "id": IDORIndicatorType.OBJECT_IDENTIFIER,
        "user_id": IDORIndicatorType.USER_IDENTIFIER,
        "userid": IDORIndicatorType.USER_IDENTIFIER,
        "account_id": IDORIndicatorType.ACCOUNT_IDENTIFIER,
        "accountid": IDORIndicatorType.ACCOUNT_IDENTIFIER,
        "profile_id": IDORIndicatorType.USER_IDENTIFIER,
        "profileid": IDORIndicatorType.USER_IDENTIFIER,
        "object_id": IDORIndicatorType.OBJECT_IDENTIFIER,
        "objectid": IDORIndicatorType.OBJECT_IDENTIFIER,
        "resource_id": IDORIndicatorType.OBJECT_IDENTIFIER,
        "resourceid": IDORIndicatorType.OBJECT_IDENTIFIER,
        "document_id": IDORIndicatorType.DOCUMENT_IDENTIFIER,
        "documentid": IDORIndicatorType.DOCUMENT_IDENTIFIER,
        "file_id": IDORIndicatorType.FILE_IDENTIFIER,
        "fileid": IDORIndicatorType.FILE_IDENTIFIER,
        "order_id": IDORIndicatorType.ORDER_IDENTIFIER,
        "orderid": IDORIndicatorType.ORDER_IDENTIFIER,
        "invoice_id": IDORIndicatorType.INVOICE_IDENTIFIER,
        "invoiceid": IDORIndicatorType.INVOICE_IDENTIFIER,
        "project_id": IDORIndicatorType.PROJECT_IDENTIFIER,
        "projectid": IDORIndicatorType.PROJECT_IDENTIFIER,
    }

    PATH_MARKERS = {
        "/users/": IDORIndicatorType.USER_IDENTIFIER,
        "/user/": IDORIndicatorType.USER_IDENTIFIER,
        "/accounts/": IDORIndicatorType.ACCOUNT_IDENTIFIER,
        "/account/": IDORIndicatorType.ACCOUNT_IDENTIFIER,
        "/profiles/": IDORIndicatorType.USER_IDENTIFIER,
        "/profile/": IDORIndicatorType.USER_IDENTIFIER,
        "/objects/": IDORIndicatorType.OBJECT_IDENTIFIER,
        "/object/": IDORIndicatorType.OBJECT_IDENTIFIER,
        "/documents/": IDORIndicatorType.DOCUMENT_IDENTIFIER,
        "/document/": IDORIndicatorType.DOCUMENT_IDENTIFIER,
        "/files/": IDORIndicatorType.FILE_IDENTIFIER,
        "/file/": IDORIndicatorType.FILE_IDENTIFIER,
        "/orders/": IDORIndicatorType.ORDER_IDENTIFIER,
        "/order/": IDORIndicatorType.ORDER_IDENTIFIER,
        "/invoices/": IDORIndicatorType.INVOICE_IDENTIFIER,
        "/invoice/": IDORIndicatorType.INVOICE_IDENTIFIER,
        "/projects/": IDORIndicatorType.PROJECT_IDENTIFIER,
        "/project/": IDORIndicatorType.PROJECT_IDENTIFIER,
        "/api/": IDORIndicatorType.API_RESOURCE,
    }

    def analyze(
        self,
        *,
        method: str,
        url: str,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> IDORAnalysis:
        if not method.strip():
            raise ValueError("method must not be empty")

        if not url.strip():
            raise ValueError("url must not be empty")

        parsed = urlparse(url)

        query_parameters = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        params = params or {}
        headers = headers or {}
        cookies = cookies or {}

        indicators: list[IDORIndicator] = []

        combined_parameters = list(params.items())
        combined_parameters.extend(query_parameters)

        seen_parameters: set[tuple[str, str]] = set()

        for name, value in combined_parameters:
            key = (name, value)

            if key in seen_parameters:
                continue

            seen_parameters.add(key)

            indicator_type = self.RESOURCE_PARAMETER_TYPES.get(
                name.lower()
            )

            if indicator_type is not None:
                indicators.append(
                    IDORIndicator(
                        type=indicator_type,
                        name="resource_parameter",
                        value=f"{name}={value}",
                    )
                )

                indicators.append(
                    IDORIndicator(
                        type=IDORIndicatorType.RESOURCE_PARAMETER,
                        name="resource_parameter",
                        value=name,
                    )
                )

            if self._looks_numeric(value):
                indicators.append(
                    IDORIndicator(
                        type=IDORIndicatorType.NUMERIC_IDENTIFIER,
                        name="numeric_identifier",
                        value=value,
                    )
                )

            if self._looks_uuid(value):
                indicators.append(
                    IDORIndicator(
                        type=IDORIndicatorType.UUID_IDENTIFIER,
                        name="uuid_identifier",
                        value=value,
                    )
                )

        path = parsed.path.lower()

        for marker, indicator_type in self.PATH_MARKERS.items():
            if marker in path:
                indicators.append(
                    IDORIndicator(
                        type=indicator_type,
                        name="resource_path",
                        value=marker,
                    )
                )

                indicators.append(
                    IDORIndicator(
                        type=IDORIndicatorType.RESOURCE_PATH,
                        name="resource_path",
                        value=marker,
                    )
                )

        if self._has_authentication_context(headers):
            indicators.append(
                IDORIndicator(
                    type=IDORIndicatorType.AUTHENTICATION_CONTEXT,
                    name="authentication_context",
                )
            )

        if self._has_session_context(cookies):
            indicators.append(
                IDORIndicator(
                    type=IDORIndicatorType.SESSION_CONTEXT,
                    name="session_context",
                )
            )

        unique: list[IDORIndicator] = []
        seen: set[
            tuple[IDORIndicatorType, str, str | None]
        ] = set()

        for indicator in indicators:
            key = (
                indicator.type,
                indicator.name,
                indicator.value,
            )

            if key not in seen:
                seen.add(key)
                unique.append(indicator)

        return IDORAnalysis(
            detected=bool(unique),
            indicators=unique,
        )

    @staticmethod
    def _looks_numeric(value: str) -> bool:
        value = value.strip()
        return bool(value) and value.isdigit()

    @staticmethod
    def _looks_uuid(value: str) -> bool:
        value = value.strip().lower()
        parts = value.split("-")

        return (
            len(parts) == 5
            and len(parts[0]) == 8
            and len(parts[1]) == 4
            and len(parts[2]) == 4
            and len(parts[3]) == 4
            and len(parts[4]) == 12
            and all(
                all(
                    char in "0123456789abcdef"
                    for char in part
                )
                for part in parts
            )
        )

    @staticmethod
    def _has_authentication_context(
        headers: dict[str, str],
    ) -> bool:
        return any(
            name.lower()
            in {
                "authorization",
                "proxy-authorization",
            }
            and bool(value.strip())
            for name, value in headers.items()
        )

    @staticmethod
    def _has_session_context(
        cookies: dict[str, str],
    ) -> bool:
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

        return any(
            name.lower() in session_names
            for name in cookies
        )
