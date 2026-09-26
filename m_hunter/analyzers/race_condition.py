from dataclasses import dataclass
from enum import Enum


class RaceConditionIndicatorType(str, Enum):
    CONCURRENT_REQUEST = "concurrent_request"
    REPEATED_REQUEST = "repeated_request"
    STATE_CHANGE = "state_change"
    DUPLICATE_OPERATION = "duplicate_operation"
    NON_IDEMPOTENT_OPERATION = "non_idempotent_operation"
    SENSITIVE_OPERATION = "sensitive_operation"
    BALANCE_CHANGE = "balance_change"
    COUPON_REDEMPTION = "coupon_redemption"
    PASSWORD_CHANGE = "password_change"
    MFA_OPERATION = "mfa_operation"
    TOKEN_ROTATION = "token_rotation"
    RESOURCE_CREATION = "resource_creation"
    RESOURCE_DELETION = "resource_deletion"
    RESPONSE_VARIATION = "response_variation"


@dataclass(frozen=True)
class RaceConditionIndicator:
    type: RaceConditionIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass
class RaceConditionAnalysis:
    indicators: list[RaceConditionIndicator]

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> list[RaceConditionIndicatorType]:
        return list(dict.fromkeys(i.type for i in self.indicators))

    @property
    def names(self) -> list[str]:
        return [
            i.name
            for i in self.indicators
            if i.name is not None
        ]

    def has_type(self, indicator_type: RaceConditionIndicatorType) -> bool:
        return any(i.type == indicator_type for i in self.indicators)


class RaceConditionAnalyzer:
    SENSITIVE_MARKERS = {
        "balance",
        "transfer",
        "payment",
        "withdraw",
        "deposit",
        "coupon",
        "redeem",
        "discount",
        "password",
        "mfa",
        "otp",
        "token",
        "session",
        "create",
        "delete",
        "remove",
        "update",
    }

    NON_IDEMPOTENT_METHODS = {"POST", "PATCH", "DELETE"}

    def analyze(
        self,
        *,
        method: str | None = None,
        url: str | None = None,
        params: dict[str, str] | None = None,
        body: str | bytes | None = None,
        concurrent_requests: int = 0,
        repeated_requests: int = 0,
        state_changed: bool = False,
        duplicate_operation: bool = False,
        response_variation: bool = False,
        balance_changed: bool = False,
        coupon_redeemed: bool = False,
        password_changed: bool = False,
        mfa_operation: bool = False,
        token_rotated: bool = False,
        resource_created: bool = False,
        resource_deleted: bool = False,
    ) -> RaceConditionAnalysis:
        if method is not None and not isinstance(method, str):
            raise TypeError("method must be a string or None")

        if url is not None and not isinstance(url, str):
            raise TypeError("url must be a string or None")

        if params is not None and not isinstance(params, dict):
            raise TypeError("params must be a dictionary or None")

        if body is not None and not isinstance(body, (str, bytes)):
            raise TypeError("body must be str, bytes, or None")

        if concurrent_requests < 0:
            raise ValueError("concurrent_requests must not be negative")

        if repeated_requests < 0:
            raise ValueError("repeated_requests must not be negative")

        indicators: list[RaceConditionIndicator] = []

        method_upper = method.upper() if method else ""
        searchable = " ".join(
            value.lower()
            for value in [
                url or "",
                *(params.keys() if params else []),
                body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body or "",
            ]
        )

        if concurrent_requests > 1:
            indicators.append(
                RaceConditionIndicator(
                    RaceConditionIndicatorType.CONCURRENT_REQUEST,
                    f"Concurrent request count: {concurrent_requests}",
                    value=str(concurrent_requests),
                )
            )

        if repeated_requests > 1:
            indicators.append(
                RaceConditionIndicator(
                    RaceConditionIndicatorType.REPEATED_REQUEST,
                    f"Repeated request count: {repeated_requests}",
                    value=str(repeated_requests),
                )
            )

        if state_changed:
            indicators.append(
                RaceConditionIndicator(
                    RaceConditionIndicatorType.STATE_CHANGE,
                    "Application state changed during the tested operation.",
                )
            )

        if duplicate_operation:
            indicators.append(
                RaceConditionIndicator(
                    RaceConditionIndicatorType.DUPLICATE_OPERATION,
                    "The same logical operation was accepted more than once.",
                )
            )

        if method_upper in self.NON_IDEMPOTENT_METHODS:
            indicators.append(
                RaceConditionIndicator(
                    RaceConditionIndicatorType.NON_IDEMPOTENT_OPERATION,
                    f"Non-idempotent HTTP method observed: {method_upper}",
                    value=method_upper,
                )
            )

        for marker in sorted(self.SENSITIVE_MARKERS):
            if marker in searchable:
                indicator_type = RaceConditionIndicatorType.SENSITIVE_OPERATION
                indicators.append(
                    RaceConditionIndicator(
                        indicator_type,
                        f"Sensitive operation marker detected: {marker}",
                        name=marker,
                        value=marker,
                    )
                )

        explicit_indicators = [
            (balance_changed, RaceConditionIndicatorType.BALANCE_CHANGE, "Balance-related state changed."),
            (coupon_redeemed, RaceConditionIndicatorType.COUPON_REDEMPTION, "Coupon redemption state changed."),
            (password_changed, RaceConditionIndicatorType.PASSWORD_CHANGE, "Password-related state changed."),
            (mfa_operation, RaceConditionIndicatorType.MFA_OPERATION, "MFA-related operation detected."),
            (token_rotated, RaceConditionIndicatorType.TOKEN_ROTATION, "Token rotation operation detected."),
            (resource_created, RaceConditionIndicatorType.RESOURCE_CREATION, "Resource creation operation detected."),
            (resource_deleted, RaceConditionIndicatorType.RESOURCE_DELETION, "Resource deletion operation detected."),
            (response_variation, RaceConditionIndicatorType.RESPONSE_VARIATION, "Responses varied during repeated testing."),
        ]

        for enabled, indicator_type, evidence in explicit_indicators:
            if enabled:
                indicators.append(
                    RaceConditionIndicator(
                        indicator_type,
                        evidence,
                    )
                )

        return RaceConditionAnalysis(indicators=indicators)
