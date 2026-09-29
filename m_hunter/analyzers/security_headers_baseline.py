from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SecurityHeaderIndicatorType(str, Enum):
    X_CONTENT_TYPE_OPTIONS = "x_content_type_options"
    X_CONTENT_TYPE_OPTIONS_MISSING = "x_content_type_options_missing"
    NOSNIFF_MISSING = "nosniff_missing"

    X_XSS_PROTECTION = "x_xss_protection"
    X_XSS_PROTECTION_UNSAFE = "x_xss_protection_unsafe"

    EXPECT_CT = "expect_ct"
    EXPECT_CT_DEPRECATED = "expect_ct_deprecated"

    X_PERMITTED_CROSS_DOMAIN_POLICIES = "x_permitted_cross_domain_policies"
    CROSS_DOMAIN_POLICY_UNSAFE = "cross_domain_policy_unsafe"

    CLEAR_SITE_DATA = "clear_site_data"
    CLEAR_SITE_DATA_WILDCARD = "clear_site_data_wildcard"

    SECURITY_HEADERS_PRESENT = "security_headers_present"
    SECURITY_HEADERS_MISSING = "security_headers_missing"
    MULTIPLE_SECURITY_HEADER = "multiple_security_header"


@dataclass(frozen=True)
class SecurityHeaderIndicator:
    type: SecurityHeaderIndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class SecurityHeadersAnalysis:
    indicators: tuple[SecurityHeaderIndicator, ...]

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[SecurityHeaderIndicatorType, ...]:
        return tuple(item.type for item in self.indicators)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.indicators)

    def has_type(self, indicator_type: SecurityHeaderIndicatorType) -> bool:
        return indicator_type in self.types


class SecurityHeadersBaselineAnalyzer:
    name = "security_headers_baseline"
    description = "Analyze baseline HTTP security headers and unsafe configurations."

    EXPECTED_HEADERS = (
        "x-content-type-options",
        "x-xss-protection",
        "expect-ct",
        "x-permitted-cross-domain-policies",
        "clear-site-data",
    )

    def analyze(
        self,
        *,
        x_content_type_options: str | None = None,
        x_xss_protection: str | None = None,
        expect_ct: str | None = None,
        x_permitted_cross_domain_policies: str | None = None,
        clear_site_data: str | None = None,
        multiple_security_header: bool = False,
    ) -> SecurityHeadersAnalysis:
        indicators: list[SecurityHeaderIndicator] = []

        if x_content_type_options:
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.X_CONTENT_TYPE_OPTIONS,
                    "X-Content-Type-Options header is present",
                    x_content_type_options,
                )
            )

            if x_content_type_options.strip().lower() == "nosniff":
                indicators.append(
                    SecurityHeaderIndicator(
                        SecurityHeaderIndicatorType.X_CONTENT_TYPE_OPTIONS,
                        "X-Content-Type-Options uses nosniff",
                        x_content_type_options,
                    )
                )
            else:
                indicators.append(
                    SecurityHeaderIndicator(
                        SecurityHeaderIndicatorType.NOSNIFF_MISSING,
                        "X-Content-Type-Options does not use nosniff",
                        x_content_type_options,
                    )
                )
        else:
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.X_CONTENT_TYPE_OPTIONS_MISSING,
                    "X-Content-Type-Options header is missing",
                    "X-Content-Type-Options: <missing>",
                )
            )
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.NOSNIFF_MISSING,
                    "nosniff protection is missing",
                )
            )

        if x_xss_protection:
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.X_XSS_PROTECTION,
                    "X-XSS-Protection header is present",
                    x_xss_protection,
                )
            )

            if x_xss_protection.strip() in {"1", "1; mode=block"}:
                indicators.append(
                    SecurityHeaderIndicator(
                        SecurityHeaderIndicatorType.X_XSS_PROTECTION_UNSAFE,
                        "X-XSS-Protection uses a legacy active configuration",
                        x_xss_protection,
                    )
                )

        if expect_ct:
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.EXPECT_CT,
                    "Expect-CT header is present",
                    expect_ct,
                )
            )
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.EXPECT_CT_DEPRECATED,
                    "Expect-CT is deprecated",
                    expect_ct,
                )
            )

        if x_permitted_cross_domain_policies:
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.X_PERMITTED_CROSS_DOMAIN_POLICIES,
                    "X-Permitted-Cross-Domain-Policies header is present",
                    x_permitted_cross_domain_policies,
                )
            )

            if x_permitted_cross_domain_policies.strip().lower() in {
                "all",
                "master-only",
            }:
                indicators.append(
                    SecurityHeaderIndicator(
                        SecurityHeaderIndicatorType.CROSS_DOMAIN_POLICY_UNSAFE,
                        "Cross-domain policy permits broader access",
                        x_permitted_cross_domain_policies,
                    )
                )

        if clear_site_data:
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.CLEAR_SITE_DATA,
                    "Clear-Site-Data header is present",
                    clear_site_data,
                )
            )

            if "*" in clear_site_data:
                indicators.append(
                    SecurityHeaderIndicator(
                        SecurityHeaderIndicatorType.CLEAR_SITE_DATA_WILDCARD,
                        "Clear-Site-Data uses wildcard clearing",
                        clear_site_data,
                    )
                )

        present_count = sum(
            value is not None
            for value in (
                x_content_type_options,
                x_xss_protection,
                expect_ct,
                x_permitted_cross_domain_policies,
                clear_site_data,
            )
        )

        if present_count:
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.SECURITY_HEADERS_PRESENT,
                    "Baseline security headers are present",
                    str(present_count),
                )
            )

        missing_count = 5 - present_count

        if missing_count:
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.SECURITY_HEADERS_MISSING,
                    "Baseline security headers are missing",
                    str(missing_count),
                )
            )

        if multiple_security_header:
            indicators.append(
                SecurityHeaderIndicator(
                    SecurityHeaderIndicatorType.MULTIPLE_SECURITY_HEADER,
                    "Multiple security header instances detected",
                )
            )

        return SecurityHeadersAnalysis(tuple(indicators))
