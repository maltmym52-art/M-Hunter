from typing import Any

from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.core.response import HttpResponse


class SecurityHeadersAnalyzer(BaseAnalyzer):
    name = "security_headers"
    description = "Analyzes HTTP security headers and their values"

    SECURITY_HEADERS = {
        "strict-transport-security": {
            "description": "Enforces HTTPS connections.",
        },
        "content-security-policy": {
            "description": "Controls the resources a browser may load.",
        },
        "x-content-type-options": {
            "description": "Prevents MIME type sniffing.",
        },
        "x-frame-options": {
            "description": "Controls whether the response may be framed.",
        },
        "referrer-policy": {
            "description": "Controls referrer information sent by the browser.",
        },
        "permissions-policy": {
            "description": "Controls access to browser features and APIs.",
        },
    }

    def analyze(self, response: HttpResponse) -> dict[str, Any]:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        headers = response.get_headers()

        normalized_headers = {
            name.lower(): value.strip()
            for name, value in headers.items()
        }

        present: dict[str, str] = {}
        missing: list[str] = []
        issues: list[dict[str, str]] = []

        for header_name in self.SECURITY_HEADERS:
            if header_name in normalized_headers:
                value = normalized_headers[header_name]
                present[header_name] = value
                issues.extend(
                    self._analyze_header_value(
                        header_name,
                        value,
                    )
                )
            else:
                missing.append(header_name)

        return {
            "present": present,
            "missing": missing,
            "issues": issues,
            "count_present": len(present),
            "count_missing": len(missing),
            "count_issues": len(issues),
            "total_headers_checked": len(self.SECURITY_HEADERS),
        }

    @staticmethod
    def _analyze_header_value(
        header_name: str,
        value: str,
    ) -> list[dict[str, str]]:
        issues: list[dict[str, str]] = []

        if not value:
            issues.append(
                {
                    "header": header_name,
                    "issue": "empty_value",
                    "severity": "medium",
                }
            )
            return issues

        if header_name == "strict-transport-security":
            issues.extend(
                SecurityHeadersAnalyzer._analyze_hsts(value)
            )

        elif header_name == "x-content-type-options":
            if value.lower() != "nosniff":
                issues.append(
                    {
                        "header": header_name,
                        "issue": "invalid_value",
                        "severity": "medium",
                    }
                )

        elif header_name == "x-frame-options":
            if value.upper() not in {"DENY", "SAMEORIGIN"}:
                issues.append(
                    {
                        "header": header_name,
                        "issue": "invalid_value",
                        "severity": "medium",
                    }
                )

        elif header_name == "content-security-policy":
            if not value.strip():
                issues.append(
                    {
                        "header": header_name,
                        "issue": "empty_value",
                        "severity": "medium",
                    }
                )

        return issues

    @staticmethod
    def _analyze_hsts(
        value: str,
    ) -> list[dict[str, str]]:
        directives = [
            directive.strip()
            for directive in value.split(";")
            if directive.strip()
        ]

        max_age = None

        for directive in directives:
            name, separator, directive_value = directive.partition("=")

            if name.strip().lower() == "max-age" and separator:
                try:
                    max_age = int(directive_value.strip())
                except ValueError:
                    return [
                        {
                            "header": "strict-transport-security",
                            "issue": "invalid_max_age",
                            "severity": "medium",
                        }
                    ]

        if max_age is None:
            return [
                {
                    "header": "strict-transport-security",
                    "issue": "missing_max_age",
                    "severity": "medium",
                }
            ]

        if max_age < 31536000:
            return [
                {
                    "header": "strict-transport-security",
                    "issue": "short_max_age",
                    "severity": "low",
                }
            ]

        return []
