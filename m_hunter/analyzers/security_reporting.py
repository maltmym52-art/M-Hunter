import json
from dataclasses import dataclass, field
from enum import Enum

from m_hunter.core.response import HttpResponse


class SecurityReportingIndicatorType(str, Enum):
    REPORTING_ENDPOINTS_PRESENT = "reporting_endpoints_present"
    REPORTING_ENDPOINTS_MISSING = "reporting_endpoints_missing"
    REPORT_TO_PRESENT = "report_to_present"
    REPORT_TO_MISSING = "report_to_missing"
    ENDPOINT_PRESENT = "endpoint_present"
    GROUP_PRESENT = "group_present"
    CSP_REPORT_ONLY = "csp_report_only"
    INVALID_REPORTING_ENDPOINTS = "invalid_reporting_endpoints"
    INVALID_REPORT_TO = "invalid_report_to"
    MULTIPLE_REPORTING_ENDPOINTS = "multiple_reporting_endpoints"
    MULTIPLE_REPORT_TO = "multiple_report_to"
    REPORTING_ENDPOINT_URL = "reporting_endpoint_url"


@dataclass(frozen=True)
class SecurityReportingIndicator:
    type: SecurityReportingIndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class SecurityReportingAnalysis:
    detected: bool
    indicators: tuple[SecurityReportingIndicator, ...] = field(
        default_factory=tuple
    )

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[SecurityReportingIndicatorType, ...]:
        return tuple(indicator.type for indicator in self.indicators)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(indicator.name for indicator in self.indicators)

    def has_type(
        self,
        indicator_type: SecurityReportingIndicatorType,
    ) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class SecurityReportingAnalyzer:
    name = "security_reporting"
    description = (
        "Analyze security policy reporting response headers"
    )

    def analyze(
        self,
        response: HttpResponse,
    ) -> SecurityReportingAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        indicators: list[SecurityReportingIndicator] = []

        reporting_endpoints = response.get_headers_all(
            "reporting-endpoints"
        )
        report_to_values = response.get_headers_all("report-to")
        csp_values = response.get_headers_all(
            "content-security-policy-report-only"
        )

        if reporting_endpoints:
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.REPORTING_ENDPOINTS_PRESENT,
                    name="Reporting-Endpoints header is present",
                    value=",".join(reporting_endpoints),
                )
            )

            if len(reporting_endpoints) > 1:
                indicators.append(
                    SecurityReportingIndicator(
                        type=SecurityReportingIndicatorType.MULTIPLE_REPORTING_ENDPOINTS,
                        name="Multiple Reporting-Endpoints headers are present",
                        value=",".join(reporting_endpoints),
                    )
                )

            for header_value in reporting_endpoints:
                self._analyze_reporting_endpoints(
                    header_value,
                    indicators,
                )
        else:
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.REPORTING_ENDPOINTS_MISSING,
                    name="Reporting-Endpoints header is missing",
                )
            )

        if report_to_values:
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.REPORT_TO_PRESENT,
                    name="Report-To header is present",
                    value=",".join(report_to_values),
                )
            )

            if len(report_to_values) > 1:
                indicators.append(
                    SecurityReportingIndicator(
                        type=SecurityReportingIndicatorType.MULTIPLE_REPORT_TO,
                        name="Multiple Report-To headers are present",
                        value=",".join(report_to_values),
                    )
                )

            for header_value in report_to_values:
                self._analyze_report_to(
                    header_value,
                    indicators,
                )
        else:
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.REPORT_TO_MISSING,
                    name="Report-To header is missing",
                )
            )

        if csp_values:
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.CSP_REPORT_ONLY,
                    name="Content-Security-Policy-Report-Only header is present",
                    value=",".join(csp_values),
                )
            )

        return SecurityReportingAnalysis(
            detected=bool(indicators),
            indicators=tuple(indicators),
        )

    @staticmethod
    def _analyze_reporting_endpoints(
        header_value: str,
        indicators: list[SecurityReportingIndicator],
    ) -> None:
        value = header_value.strip()

        if not value:
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS,
                    name="Reporting-Endpoints header is empty",
                    value=header_value,
                )
            )
            return

        definitions = [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

        if not definitions:
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS,
                    name="Reporting-Endpoints contains no endpoint definitions",
                    value=header_value,
                )
            )
            return

        for definition in definitions:
            if "=" not in definition:
                indicators.append(
                    SecurityReportingIndicator(
                        type=SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS,
                        name="Invalid Reporting-Endpoints definition",
                        value=definition,
                    )
                )
                continue

            name, endpoint = definition.split("=", 1)
            name = name.strip()
            endpoint = endpoint.strip()

            if not name or not endpoint:
                indicators.append(
                    SecurityReportingIndicator(
                        type=SecurityReportingIndicatorType.INVALID_REPORTING_ENDPOINTS,
                        name="Invalid Reporting-Endpoints definition",
                        value=definition,
                    )
                )
                continue

            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.ENDPOINT_PRESENT,
                    name=f"Reporting endpoint {name}",
                    value=endpoint,
                )
            )

            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.REPORTING_ENDPOINT_URL,
                    name=f"Reporting endpoint URL for {name}",
                    value=endpoint,
                )
            )

    @staticmethod
    def _analyze_report_to(
        header_value: str,
        indicators: list[SecurityReportingIndicator],
    ) -> None:
        value = header_value.strip()

        if not value:
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.INVALID_REPORT_TO,
                    name="Report-To header is empty",
                    value=header_value,
                )
            )
            return

        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.INVALID_REPORT_TO,
                    name="Report-To header contains invalid JSON",
                    value=header_value,
                )
            )
            return

        if not isinstance(parsed, dict):
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.INVALID_REPORT_TO,
                    name="Report-To value is not a JSON object",
                    value=header_value,
                )
            )
            return

        group = parsed.get("group")

        if group is not None:
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.GROUP_PRESENT,
                    name="Report-To group is present",
                    value=str(group),
                )
            )

        endpoints = parsed.get("endpoints")

        if not isinstance(endpoints, list):
            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.INVALID_REPORT_TO,
                    name="Report-To endpoints is not an array",
                    value=header_value,
                )
            )
            return

        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                indicators.append(
                    SecurityReportingIndicator(
                        type=SecurityReportingIndicatorType.INVALID_REPORT_TO,
                        name="Report-To endpoint is not an object",
                        value=str(endpoint),
                    )
                )
                continue

            url = endpoint.get("url")

            if not isinstance(url, str) or not url.strip():
                indicators.append(
                    SecurityReportingIndicator(
                        type=SecurityReportingIndicatorType.INVALID_REPORT_TO,
                        name="Report-To endpoint URL is invalid",
                        value=str(endpoint),
                    )
                )
                continue

            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.ENDPOINT_PRESENT,
                    name="Report-To endpoint is present",
                    value=url,
                )
            )

            indicators.append(
                SecurityReportingIndicator(
                    type=SecurityReportingIndicatorType.REPORTING_ENDPOINT_URL,
                    name="Report-To endpoint URL",
                    value=url,
                )
            )
