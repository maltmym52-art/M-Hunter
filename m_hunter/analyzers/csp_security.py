from dataclasses import dataclass, field
from enum import Enum

from m_hunter.core.response import HttpResponse


class CSPIndicatorType(str, Enum):
    CSP_PRESENT = "csp_present"
    CSP_REPORT_ONLY = "csp_report_only"
    WILDCARD_SOURCE = "wildcard_source"
    UNSAFE_INLINE = "unsafe_inline"
    UNSAFE_EVAL = "unsafe_eval"
    UNSAFE_HASHES = "unsafe_hashes"
    NONCE_SOURCE = "nonce_source"
    DATA_SOURCE = "data_source"
    BLOB_SOURCE = "blob_source"
    OBJECT_NONE = "object_none"
    BASE_NONE = "base_none"
    FRAME_ANCESTORS_NONE = "frame_ancestors_none"
    FRAME_ANCESTORS_WILDCARD = "frame_ancestors_wildcard"
    SCRIPT_SRC_MISSING = "script_src_missing"
    DEFAULT_SRC_MISSING = "default_src_missing"
    SCRIPT_SRC_WILDCARD = "script_src_wildcard"
    CONNECT_SRC_WILDCARD = "connect_src_wildcard"
    IMG_SRC_WILDCARD = "img_src_wildcard"
    STYLE_SRC_WILDCARD = "style_src_wildcard"
    FORM_ACTION_MISSING = "form_action_missing"
    UPGRADE_INSECURE_REQUESTS_MISSING = (
        "upgrade_insecure_requests_missing"
    )
    BLOCK_ALL_MIXED_CONTENT_MISSING = (
        "block_all_mixed_content_missing"
    )


@dataclass(frozen=True)
class CSPIndicator:
    type: CSPIndicatorType
    evidence: str
    value: str | None = None


@dataclass
class CSPAnalysis:
    detected: bool
    indicators: tuple[CSPIndicator, ...] = field(default_factory=tuple)
    count: int = 0
    types: tuple[CSPIndicatorType, ...] = field(default_factory=tuple)
    names: tuple[str, ...] = field(default_factory=tuple)

    def has_type(
        self,
        indicator_type: CSPIndicatorType,
    ) -> bool:
        return indicator_type in self.types


class CSPSecurityAnalyzer:
    name = "csp_security"
    description = (
        "Analyze Content-Security-Policy security characteristics"
    )

    def analyze(
        self,
        response: HttpResponse,
    ) -> CSPAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        indicators: list[CSPIndicator] = []

        csp = response.get_header(
            "content-security-policy"
        )
        report_only = response.get_header(
            "content-security-policy-report-only"
        )

        if csp:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.CSP_PRESENT,
                    "Content-Security-Policy header is present",
                    csp,
                )
            )

        if report_only:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.CSP_REPORT_ONLY,
                    "Content-Security-Policy-Report-Only header is present",
                    report_only,
                )
            )

        policy = csp or report_only

        if not policy:
            return self._build(indicators)

        directives = self._parse_policy(policy)

        for directive, values in directives.items():
            lower_values = {
                value.lower()
                for value in values
            }

            if "*" in lower_values:
                indicators.append(
                    CSPIndicator(
                        CSPIndicatorType.WILDCARD_SOURCE,
                        f"{directive} contains wildcard source",
                        "*",
                    )
                )

            if "'unsafe-inline'" in lower_values:
                indicators.append(
                    CSPIndicator(
                        CSPIndicatorType.UNSAFE_INLINE,
                        f"{directive} allows unsafe-inline",
                        "'unsafe-inline'",
                    )
                )

            if "'unsafe-eval'" in lower_values:
                indicators.append(
                    CSPIndicator(
                        CSPIndicatorType.UNSAFE_EVAL,
                        f"{directive} allows unsafe-eval",
                        "'unsafe-eval'",
                    )
                )

            if "'unsafe-hashes'" in lower_values:
                indicators.append(
                    CSPIndicator(
                        CSPIndicatorType.UNSAFE_HASHES,
                        f"{directive} allows unsafe-hashes",
                        "'unsafe-hashes'",
                    )
                )

            if any(
                value.lower().startswith("'nonce-")
                for value in values
            ):
                indicators.append(
                    CSPIndicator(
                        CSPIndicatorType.NONCE_SOURCE,
                        f"{directive} contains nonce source",
                    )
                )

            if "data:" in lower_values:
                indicators.append(
                    CSPIndicator(
                        CSPIndicatorType.DATA_SOURCE,
                        f"{directive} allows data: source",
                        "data:",
                    )
                )

            if "blob:" in lower_values:
                indicators.append(
                    CSPIndicator(
                        CSPIndicatorType.BLOB_SOURCE,
                        f"{directive} allows blob: source",
                        "blob:",
                    )
                )

        object_values = directives.get(
            "object-src",
            [],
        )

        if "'none'" in {
            value.lower()
            for value in object_values
        }:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.OBJECT_NONE,
                    "object-src is restricted to none",
                    "'none'",
                )
            )

        base_values = directives.get(
            "base-uri",
            [],
        )

        if "'none'" in {
            value.lower()
            for value in base_values
        }:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.BASE_NONE,
                    "base-uri is restricted to none",
                    "'none'",
                )
            )

        frame_values = directives.get(
            "frame-ancestors",
            [],
        )

        frame_lower = {
            value.lower()
            for value in frame_values
        }

        if "'none'" in frame_lower:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.FRAME_ANCESTORS_NONE,
                    "frame-ancestors is restricted to none",
                    "'none'",
                )
            )

        if "*" in frame_lower:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.FRAME_ANCESTORS_WILDCARD,
                    "frame-ancestors allows wildcard",
                    "*",
                )
            )

        if "script-src" not in directives:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.SCRIPT_SRC_MISSING,
                    "script-src directive is missing",
                )
            )

        if "default-src" not in directives:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.DEFAULT_SRC_MISSING,
                    "default-src directive is missing",
                )
            )

        if "*" in {
            value.lower()
            for value in directives.get(
                "script-src",
                [],
            )
        }:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.SCRIPT_SRC_WILDCARD,
                    "script-src allows wildcard",
                    "*",
                )
            )

        if "*" in {
            value.lower()
            for value in directives.get(
                "connect-src",
                [],
            )
        }:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.CONNECT_SRC_WILDCARD,
                    "connect-src allows wildcard",
                    "*",
                )
            )

        if "*" in {
            value.lower()
            for value in directives.get(
                "img-src",
                [],
            )
        }:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.IMG_SRC_WILDCARD,
                    "img-src allows wildcard",
                    "*",
                )
            )

        if "*" in {
            value.lower()
            for value in directives.get(
                "style-src",
                [],
            )
        }:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.STYLE_SRC_WILDCARD,
                    "style-src allows wildcard",
                    "*",
                )
            )

        if "form-action" not in directives:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.FORM_ACTION_MISSING,
                    "form-action directive is missing",
                )
            )

        if "upgrade-insecure-requests" not in directives:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.UPGRADE_INSECURE_REQUESTS_MISSING,
                    "upgrade-insecure-requests directive is missing",
                )
            )

        if "block-all-mixed-content" not in directives:
            indicators.append(
                CSPIndicator(
                    CSPIndicatorType.BLOCK_ALL_MIXED_CONTENT_MISSING,
                    "block-all-mixed-content directive is missing",
                )
            )

        return self._build(indicators)

    @staticmethod
    def _parse_policy(
        policy: str,
    ) -> dict[str, list[str]]:
        directives: dict[str, list[str]] = {}

        for raw_directive in policy.split(";"):
            parts = raw_directive.strip().split()

            if not parts:
                continue

            name = parts[0].lower()
            values = parts[1:]

            directives.setdefault(
                name,
                [],
            ).extend(values)

        return directives

    @staticmethod
    def _build(
        indicators: list[CSPIndicator],
    ) -> CSPAnalysis:
        types = tuple(
            dict.fromkeys(
                indicator.type
                for indicator in indicators
            )
        )

        return CSPAnalysis(
            detected=bool(indicators),
            indicators=tuple(indicators),
            count=len(indicators),
            types=types,
            names=tuple(
                indicator_type.value
                for indicator_type in types
            ),
        )
