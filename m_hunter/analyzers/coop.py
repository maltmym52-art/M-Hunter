from dataclasses import dataclass, field
from enum import Enum

from m_hunter.core.response import HttpResponse


class COOPIndicatorType(str, Enum):
    POLICY_PRESENT = "policy_present"
    POLICY_MISSING = "policy_missing"
    SAME_ORIGIN = "same_origin"
    SAME_ORIGIN_ALLOW_POPUPS = "same_origin_allow_popups"
    UNSAFE_NONE = "unsafe_none"
    INVALID_POLICY = "invalid_policy"
    MULTIPLE_POLICIES = "multiple_policies"


@dataclass(frozen=True)
class COOPIndicator:
    type: COOPIndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class COOPAnalysis:
    detected: bool
    indicators: tuple[COOPIndicator, ...] = field(
        default_factory=tuple
    )

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[COOPIndicatorType, ...]:
        return tuple(indicator.type for indicator in self.indicators)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(indicator.name for indicator in self.indicators)

    def has_type(self, indicator_type: COOPIndicatorType) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class COOPAnalyzer:
    name = "coop"
    description = "Analyze Cross-Origin-Opener-Policy response headers"

    _POLICIES = {
        "same-origin": COOPIndicatorType.SAME_ORIGIN,
        "same-origin-allow-popups": (
            COOPIndicatorType.SAME_ORIGIN_ALLOW_POPUPS
        ),
        "unsafe-none": COOPIndicatorType.UNSAFE_NONE,
    }

    def analyze(self, response: HttpResponse) -> COOPAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        indicators: list[COOPIndicator] = []
        values = response.get_headers_all(
            "cross-origin-opener-policy"
        )

        if not values:
            indicators.append(
                COOPIndicator(
                    COOPIndicatorType.POLICY_MISSING,
                    "Cross-Origin-Opener-Policy",
                )
            )
            return COOPAnalysis(
                detected=True,
                indicators=tuple(indicators),
            )

        indicators.append(
            COOPIndicator(
                COOPIndicatorType.POLICY_PRESENT,
                "Cross-Origin-Opener-Policy",
                values[0],
            )
        )

        if len(values) > 1:
            indicators.append(
                COOPIndicator(
                    COOPIndicatorType.MULTIPLE_POLICIES,
                    "Cross-Origin-Opener-Policy",
                    ", ".join(values),
                )
            )

        for header_value in values:
            for token in header_value.split(","):
                policy = token.strip().lower()

                if not policy:
                    continue

                indicator_type = self._POLICIES.get(policy)

                if indicator_type is None:
                    indicators.append(
                        COOPIndicator(
                            COOPIndicatorType.INVALID_POLICY,
                            policy,
                            policy,
                        )
                    )
                    continue

                indicators.append(
                    COOPIndicator(
                        indicator_type,
                        policy,
                        policy,
                    )
                )

        return COOPAnalysis(
            detected=True,
            indicators=tuple(indicators),
        )
