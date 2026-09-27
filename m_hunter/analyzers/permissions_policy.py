from dataclasses import dataclass, field
from enum import Enum

from m_hunter.core.response import HttpResponse


class PermissionsPolicyIndicatorType(str, Enum):
    POLICY_PRESENT = "policy_present"
    POLICY_MISSING = "policy_missing"
    WILDCARD_SOURCE = "wildcard_source"
    SELF_SOURCE = "self_source"
    ORIGIN_SOURCE = "origin_source"
    CAMERA = "camera"
    MICROPHONE = "microphone"
    GEOLOCATION = "geolocation"
    PAYMENT = "payment"
    USB = "usb"
    FULLSCREEN = "fullscreen"
    DISPLAY_CAPTURE = "display_capture"
    INVALID_DIRECTIVE = "invalid_directive"
    INVALID_SOURCE = "invalid_source"
    MULTIPLE_POLICIES = "multiple_policies"


@dataclass(frozen=True)
class PermissionsPolicyIndicator:
    type: PermissionsPolicyIndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class PermissionsPolicyAnalysis:
    detected: bool
    indicators: tuple[PermissionsPolicyIndicator, ...] = field(
        default_factory=tuple
    )

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[PermissionsPolicyIndicatorType, ...]:
        return tuple(indicator.type for indicator in self.indicators)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(indicator.name for indicator in self.indicators)

    def has_type(self, indicator_type: PermissionsPolicyIndicatorType) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class PermissionsPolicyAnalyzer:
    name = "permissions_policy"
    description = "Analyze Permissions-Policy response headers"

    _KNOWN_FEATURES = {
        "camera": PermissionsPolicyIndicatorType.CAMERA,
        "microphone": PermissionsPolicyIndicatorType.MICROPHONE,
        "geolocation": PermissionsPolicyIndicatorType.GEOLOCATION,
        "payment": PermissionsPolicyIndicatorType.PAYMENT,
        "usb": PermissionsPolicyIndicatorType.USB,
        "fullscreen": PermissionsPolicyIndicatorType.FULLSCREEN,
        "display-capture": PermissionsPolicyIndicatorType.DISPLAY_CAPTURE,
    }

    def analyze(
        self,
        response: HttpResponse,
    ) -> PermissionsPolicyAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        indicators: list[PermissionsPolicyIndicator] = []
        values = response.get_headers_all("permissions-policy")

        if not values:
            indicators.append(
                PermissionsPolicyIndicator(
                    PermissionsPolicyIndicatorType.POLICY_MISSING,
                    "Permissions-Policy",
                )
            )
            return PermissionsPolicyAnalysis(
                detected=True,
                indicators=tuple(indicators),
            )

        indicators.append(
            PermissionsPolicyIndicator(
                PermissionsPolicyIndicatorType.POLICY_PRESENT,
                "Permissions-Policy",
                values[0],
            )
        )

        if len(values) > 1:
            indicators.append(
                PermissionsPolicyIndicator(
                    PermissionsPolicyIndicatorType.MULTIPLE_POLICIES,
                    "Permissions-Policy",
                    ", ".join(values),
                )
            )

        for header_value in values:
            directives = [
                part.strip()
                for part in header_value.split(",")
                if part.strip()
            ]

            for directive in directives:
                parts = directive.split()
                if not parts:
                    continue

                feature = parts[0].lower()
                if "=" in feature:
                    feature = feature.split("=", 1)[0].strip()

                if feature not in self._KNOWN_FEATURES:
                    indicators.append(
                        PermissionsPolicyIndicator(
                            PermissionsPolicyIndicatorType.INVALID_DIRECTIVE,
                            feature,
                            directive,
                        )
                    )
                    continue

                indicator_type = self._KNOWN_FEATURES[feature]
                indicators.append(
                    PermissionsPolicyIndicator(
                        indicator_type,
                        feature,
                        directive,
                    )
                )

                sources = parts[1:]

                for source in sources:
                    normalized = source.strip().lower()

                    if normalized == "*":
                        indicators.append(
                            PermissionsPolicyIndicator(
                                PermissionsPolicyIndicatorType.WILDCARD_SOURCE,
                                feature,
                                source,
                            )
                        )
                    elif normalized == "self":
                        indicators.append(
                            PermissionsPolicyIndicator(
                                PermissionsPolicyIndicatorType.SELF_SOURCE,
                                feature,
                                source,
                            )
                        )
                    elif normalized.startswith(("http://", "https://")):
                        indicators.append(
                            PermissionsPolicyIndicator(
                                PermissionsPolicyIndicatorType.ORIGIN_SOURCE,
                                feature,
                                source,
                            )
                        )
                    elif normalized.startswith("(") or normalized.endswith(")"):
                        continue
                    else:
                        indicators.append(
                            PermissionsPolicyIndicator(
                                PermissionsPolicyIndicatorType.INVALID_SOURCE,
                                feature,
                                source,
                            )
                        )

        return PermissionsPolicyAnalysis(
            detected=True,
            indicators=tuple(indicators),
        )
