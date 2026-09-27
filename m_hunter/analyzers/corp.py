from dataclasses import dataclass, field
from enum import Enum

from m_hunter.core.response import HttpResponse


class CORPIndicatorType(str, Enum):
    POLICY_PRESENT = "policy_present"
    POLICY_MISSING = "policy_missing"
    SAME_ORIGIN = "same_origin"
    SAME_SITE = "same_site"
    CROSS_ORIGIN = "cross_origin"
    INVALID_POLICY = "invalid_policy"
    MULTIPLE_POLICIES = "multiple_policies"


@dataclass(frozen=True)
class CORPIndicator:
    type: CORPIndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class CORPAnalysis:
    detected: bool
    indicators: tuple[CORPIndicator, ...] = field(default_factory=tuple)

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[CORPIndicatorType, ...]:
        return tuple(indicator.type for indicator in self.indicators)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(indicator.name for indicator in self.indicators)

    def has_type(self, indicator_type: CORPIndicatorType) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class CORPAnalyzer:
    name = "corp"
    description = (
        "Analyze Cross-Origin-Resource-Policy response headers"
    )

    _POLICIES = {
        "same-origin": CORPIndicatorType.SAME_ORIGIN,
        "same-site": CORPIndicatorType.SAME_SITE,
        "cross-origin": CORPIndicatorType.CROSS_ORIGIN,
    }

    def analyze(self, response: HttpResponse) -> CORPAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError("response must be an instance of HttpResponse")

        values = response.get_headers_all(
            "cross-origin-resource-policy"
        )

        if not values:
            return CORPAnalysis(
                detected=True,
                indicators=(
                    CORPIndicator(
                        type=CORPIndicatorType.POLICY_MISSING,
                        name="Cross-Origin-Resource-Policy header is missing",
                    ),
                ),
            )

        indicators: list[CORPIndicator] = [
            CORPIndicator(
                type=CORPIndicatorType.POLICY_PRESENT,
                name="Cross-Origin-Resource-Policy header is present",
                value=",".join(values),
            )
        ]

        if len(values) > 1:
            indicators.append(
                CORPIndicator(
                    type=CORPIndicatorType.MULTIPLE_POLICIES,
                    name="Multiple Cross-Origin-Resource-Policy values",
                    value=",".join(values),
                )
            )

        for header_value in values:
            tokens = [
                token.strip().lower()
                for token in header_value.split(",")
                if token.strip()
            ]

            if not tokens:
                indicators.append(
                    CORPIndicator(
                        type=CORPIndicatorType.INVALID_POLICY,
                        name="Empty Cross-Origin-Resource-Policy policy",
                        value=header_value,
                    )
                )
                continue

            for token in tokens:
                indicator_type = self._POLICIES.get(token)

                if indicator_type is None:
                    indicators.append(
                        CORPIndicator(
                            type=CORPIndicatorType.INVALID_POLICY,
                            name="Invalid Cross-Origin-Resource-Policy policy",
                            value=token,
                        )
                    )
                    continue

                indicators.append(
                    CORPIndicator(
                        type=indicator_type,
                        name=f"Cross-Origin-Resource-Policy {token}",
                        value=token,
                    )
                )

        return CORPAnalysis(
            detected=True,
            indicators=tuple(indicators),
        )
