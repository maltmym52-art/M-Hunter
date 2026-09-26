from dataclasses import dataclass, field
from enum import Enum

from m_hunter.core.response import HttpResponse


class ClickjackingIndicatorType(str, Enum):
    MISSING_X_FRAME_OPTIONS = "missing_x_frame_options"
    X_FRAME_OPTIONS_DENY = "x_frame_options_deny"
    X_FRAME_OPTIONS_SAMEORIGIN = "x_frame_options_sameorigin"
    X_FRAME_OPTIONS_ALLOW_FROM = "x_frame_options_allow_from"
    INVALID_X_FRAME_OPTIONS = "invalid_x_frame_options"
    MISSING_FRAME_ANCESTORS = "missing_frame_ancestors"
    FRAME_ANCESTORS_NONE = "frame_ancestors_none"
    FRAME_ANCESTORS_SELF = "frame_ancestors_self"
    FRAME_ANCESTORS_WILDCARD = "frame_ancestors_wildcard"
    FRAME_ANCESTORS_ORIGIN = "frame_ancestors_origin"
    CSP_PRESENT = "csp_present"


@dataclass(frozen=True)
class ClickjackingIndicator:
    type: ClickjackingIndicatorType
    name: str
    value: str | None = None


@dataclass
class ClickjackingAnalysis:
    detected: bool
    indicators: list[ClickjackingIndicator] = field(
        default_factory=list
    )

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[ClickjackingIndicatorType, ...]:
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
        indicator_type: ClickjackingIndicatorType,
    ) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class ClickjackingAnalyzer:
    """
    Analyzes response headers relevant to clickjacking protection.

    This analyzer identifies framing policy and configuration
    indicators. A missing or weak policy is an indicator and does
    not by itself prove an exploitable clickjacking condition.
    """

    def analyze(
        self,
        response: HttpResponse,
    ) -> ClickjackingAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        indicators: list[ClickjackingIndicator] = []

        xfo = response.get_header("x-frame-options")
        csp = response.get_header("content-security-policy")

        if xfo is None:
            indicators.append(
                ClickjackingIndicator(
                    type=ClickjackingIndicatorType.MISSING_X_FRAME_OPTIONS,
                    name="missing_x_frame_options",
                )
            )
        else:
            normalized_xfo = xfo.strip().upper()

            if normalized_xfo == "DENY":
                indicators.append(
                    ClickjackingIndicator(
                        type=ClickjackingIndicatorType.X_FRAME_OPTIONS_DENY,
                        name="x_frame_options_deny",
                        value=xfo,
                    )
                )

            elif normalized_xfo == "SAMEORIGIN":
                indicators.append(
                    ClickjackingIndicator(
                        type=ClickjackingIndicatorType.X_FRAME_OPTIONS_SAMEORIGIN,
                        name="x_frame_options_sameorigin",
                        value=xfo,
                    )
                )

            elif normalized_xfo.startswith("ALLOW-FROM"):
                indicators.append(
                    ClickjackingIndicator(
                        type=ClickjackingIndicatorType.X_FRAME_OPTIONS_ALLOW_FROM,
                        name="x_frame_options_allow_from",
                        value=xfo,
                    )
                )

            else:
                indicators.append(
                    ClickjackingIndicator(
                        type=ClickjackingIndicatorType.INVALID_X_FRAME_OPTIONS,
                        name="invalid_x_frame_options",
                        value=xfo,
                    )
                )

        if csp is not None:
            indicators.append(
                ClickjackingIndicator(
                    type=ClickjackingIndicatorType.CSP_PRESENT,
                    name="csp_present",
                    value=csp,
                )
            )

            frame_ancestors = self._extract_frame_ancestors(csp)

            if frame_ancestors is None:
                indicators.append(
                    ClickjackingIndicator(
                        type=ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS,
                        name="missing_frame_ancestors",
                    )
                )
            else:
                directive = frame_ancestors.strip()

                if directive == "'none'":
                    indicator_type = (
                        ClickjackingIndicatorType.FRAME_ANCESTORS_NONE
                    )

                elif directive == "'self'":
                    indicator_type = (
                        ClickjackingIndicatorType.FRAME_ANCESTORS_SELF
                    )

                elif "*" in directive.split():
                    indicator_type = (
                        ClickjackingIndicatorType.FRAME_ANCESTORS_WILDCARD
                    )

                else:
                    indicator_type = (
                        ClickjackingIndicatorType.FRAME_ANCESTORS_ORIGIN
                    )

                indicators.append(
                    ClickjackingIndicator(
                        type=indicator_type,
                        name=indicator_type.value,
                        value=directive,
                    )
                )

        else:
            indicators.append(
                ClickjackingIndicator(
                    type=ClickjackingIndicatorType.MISSING_FRAME_ANCESTORS,
                    name="missing_frame_ancestors",
                )
            )

        unique: list[ClickjackingIndicator] = []
        seen: set[tuple[
            ClickjackingIndicatorType,
            str,
            str | None,
        ]] = set()

        for indicator in indicators:
            key = (
                indicator.type,
                indicator.name,
                indicator.value,
            )

            if key not in seen:
                seen.add(key)
                unique.append(indicator)

        return ClickjackingAnalysis(
            detected=bool(unique),
            indicators=unique,
        )

    @staticmethod
    def _extract_frame_ancestors(
        csp: str,
    ) -> str | None:
        for directive in csp.split(";"):
            directive = directive.strip()

            if not directive:
                continue

            parts = directive.split()

            if not parts:
                continue

            if parts[0].lower() == "frame-ancestors":
                return " ".join(parts[1:])

        return None
