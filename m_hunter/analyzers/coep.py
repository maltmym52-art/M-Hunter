from dataclasses import dataclass, field
from enum import Enum

from m_hunter.core.response import HttpResponse


class COEPIndicatorType(str, Enum):
    POLICY_PRESENT = "policy_present"
    POLICY_MISSING = "policy_missing"
    REQUIRE_CORP = "require_corp"
    CREDENTIALLESS = "credentialless"
    UNSAFE_NONE = "unsafe_none"
    INVALID_POLICY = "invalid_policy"
    MULTIPLE_POLICIES = "multiple_policies"


@dataclass(frozen=True)
class COEPIndicator:
    type: COEPIndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class COEPAnalysis:
    detected: bool
    indicators: tuple[COEPIndicator, ...] = field(
        default_factory=tuple
    )

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[COEPIndicatorType, ...]:
        return tuple(
            indicator.type
            for indicator in self.indicators
        )

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(
            indicator.name
            for indicator in self.indicators
        )

    def has_type(
        self,
        indicator_type: COEPIndicatorType,
    ) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class COEPAnalyzer:
    name = "coep"
    description = (
        "Analyze Cross-Origin-Embedder-Policy response headers"
    )

    _POLICIES = {
        "require-corp": COEPIndicatorType.REQUIRE_CORP,
        "credentialless": COEPIndicatorType.CREDENTIALLESS,
        "unsafe-none": COEPIndicatorType.UNSAFE_NONE,
    }

    def analyze(
        self,
        response: HttpResponse,
    ) -> COEPAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        indicators: list[COEPIndicator] = []

        values = response.get_headers_all(
            "cross-origin-embedder-policy"
        )

        if not values:
            indicators.append(
                COEPIndicator(
                    COEPIndicatorType.POLICY_MISSING,
                    "Cross-Origin-Embedder-Policy",
                )
            )

            return COEPAnalysis(
                detected=True,
                indicators=tuple(indicators),
            )

        indicators.append(
            COEPIndicator(
                COEPIndicatorType.POLICY_PRESENT,
                "Cross-Origin-Embedder-Policy",
                values[0],
            )
        )

        if len(values) > 1:
            indicators.append(
                COEPIndicator(
                    COEPIndicatorType.MULTIPLE_POLICIES,
                    "Cross-Origin-Embedder-Policy",
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
                        COEPIndicator(
                            COEPIndicatorType.INVALID_POLICY,
                            policy,
                            policy,
                        )
                    )
                    continue

                indicators.append(
                    COEPIndicator(
                        indicator_type,
                        policy,
                        policy,
                    )
                )

        return COEPAnalysis(
            detected=True,
            indicators=tuple(indicators),
        )
