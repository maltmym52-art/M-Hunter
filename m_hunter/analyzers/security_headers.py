from typing import Any

from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.core.response import HttpResponse


class SecurityHeadersAnalyzer(BaseAnalyzer):
    name = "security_headers"
    description = "Analyzes HTTP security headers"

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
        headers = response.get_headers()

        normalized_headers = {
            name.lower(): value
            for name, value in headers.items()
        }

        present: dict[str, str] = {}
        missing: list[str] = []

        for header_name in self.SECURITY_HEADERS:
            if header_name in normalized_headers:
                present[header_name] = normalized_headers[header_name]
            else:
                missing.append(header_name)

        return {
            "present": present,
            "missing": missing,
            "count_present": len(present),
            "count_missing": len(missing),
            "total_headers_checked": len(self.SECURITY_HEADERS),
        }
