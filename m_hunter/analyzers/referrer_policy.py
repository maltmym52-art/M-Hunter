from dataclasses import dataclass, field
from enum import Enum

from m_hunter.core.response import HttpResponse


class ReferrerPolicyIndicatorType(str, Enum):
    POLICY_PRESENT = "policy_present"
    POLICY_MISSING = "policy_missing"
    UNSAFE_URL = "unsafe_url"
    NO_REFERRER_WHEN_DOWNGRADE = "no_referrer_when_downgrade"
    ORIGIN_WHEN_CROSS_ORIGIN = "origin_when_cross_origin"
    STRICT_ORIGIN_WHEN_CROSS_ORIGIN = (
        "strict_origin_when_cross_origin"
    )
    SAME_ORIGIN = "same_origin"
    STRICT_ORIGIN = "strict_origin"
    NO_REFERRER = "no_referrer"
    INVALID_POLICY = "invalid_policy"
    MULTIPLE_POLICIES = "multiple_policies"


@dataclass(frozen=True)
class ReferrerPolicyIndicator:
    type: ReferrerPolicyIndicatorType
    evidence: str
    value: str | None = None


@dataclass
class ReferrerPolicyAnalysis:
    detected: bool
    indicators: tuple[ReferrerPolicyIndicator, ...] = field(
        default_factory=tuple
    )
    count: int = 0
    types: tuple[ReferrerPolicyIndicatorType, ...] = field(
        default_factory=tuple
    )
    names: tuple[str, ...] = field(default_factory=tuple)

    def has_type(
        self,
        indicator_type: ReferrerPolicyIndicatorType,
    ) -> bool:
        return indicator_type in self.types


class ReferrerPolicyAnalyzer:
    name = "referrer_policy"
    description = "Analyze Referrer-Policy security characteristics"

    VALID_POLICIES = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }

    def analyze(
        self,
        response: HttpResponse,
    ) -> ReferrerPolicyAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        indicators: list[ReferrerPolicyIndicator] = []

        values = response.get_headers_all(
            "referrer-policy"
        )

        if not values:
            indicators.append(
                ReferrerPolicyIndicator(
                    ReferrerPolicyIndicatorType.POLICY_MISSING,
                    "Referrer-Policy header is missing",
                )
            )
            return self._build(indicators)

        indicators.append(
            ReferrerPolicyIndicator(
                ReferrerPolicyIndicatorType.POLICY_PRESENT,
                "Referrer-Policy header is present",
                values[0],
            )
        )

        tokens: list[str] = []

        for value in values:
            for token in value.split(","):
                token = token.strip().lower()
                if token:
                    tokens.append(token)

        unique_tokens = list(dict.fromkeys(tokens))

        if len(unique_tokens) > 1:
            indicators.append(
                ReferrerPolicyIndicator(
                    ReferrerPolicyIndicatorType.MULTIPLE_POLICIES,
                    "Multiple Referrer-Policy values are present",
                    ", ".join(unique_tokens),
                )
            )

        invalid = [
            token
            for token in unique_tokens
            if token not in self.VALID_POLICIES
        ]

        if invalid:
            indicators.append(
                ReferrerPolicyIndicator(
                    ReferrerPolicyIndicatorType.INVALID_POLICY,
                    "Referrer-Policy contains an invalid policy value",
                    ", ".join(invalid),
                )
            )

        for token in unique_tokens:
            indicator_type = {
                "unsafe-url":
                    ReferrerPolicyIndicatorType.UNSAFE_URL,
                "no-referrer-when-downgrade":
                    ReferrerPolicyIndicatorType.NO_REFERRER_WHEN_DOWNGRADE,
                "origin-when-cross-origin":
                    ReferrerPolicyIndicatorType.ORIGIN_WHEN_CROSS_ORIGIN,
                "strict-origin-when-cross-origin":
                    ReferrerPolicyIndicatorType.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
                "same-origin":
                    ReferrerPolicyIndicatorType.SAME_ORIGIN,
                "strict-origin":
                    ReferrerPolicyIndicatorType.STRICT_ORIGIN,
                "no-referrer":
                    ReferrerPolicyIndicatorType.NO_REFERRER,
            }.get(token)

            if indicator_type is not None:
                indicators.append(
                    ReferrerPolicyIndicator(
                        indicator_type,
                        f"Referrer-Policy uses {token}",
                        token,
                    )
                )

        return self._build(indicators)

    @staticmethod
    def _build(
        indicators: list[ReferrerPolicyIndicator],
    ) -> ReferrerPolicyAnalysis:
        types = tuple(
            dict.fromkeys(
                indicator.type
                for indicator in indicators
            )
        )

        return ReferrerPolicyAnalysis(
            detected=bool(indicators),
            indicators=tuple(indicators),
            count=len(indicators),
            types=types,
            names=tuple(
                indicator_type.value
                for indicator_type in types
            ),
        )
