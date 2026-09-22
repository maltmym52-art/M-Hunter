from m_hunter.core.finding import Finding
from m_hunter.core.http import HttpEngine
from m_hunter.core.target import Target
from m_hunter.scanners.base import BaseScanner


class SecurityHeadersScanner(BaseScanner):
    name = "security_headers"
    description = "Checks for missing HTTP security headers"

    REQUIRED_HEADERS = {
        "strict-transport-security": {
            "title": "Missing Strict-Transport-Security Header",
            "severity": "Medium",
            "description": "The response does not include the Strict-Transport-Security header.",
            "remediation": "Configure Strict-Transport-Security for HTTPS responses.",
        },
        "content-security-policy": {
            "title": "Missing Content-Security-Policy Header",
            "severity": "Medium",
            "description": "The response does not include a Content-Security-Policy header.",
            "remediation": "Define an appropriate Content-Security-Policy.",
        },
        "x-content-type-options": {
            "title": "Missing X-Content-Type-Options Header",
            "severity": "Low",
            "description": "The response does not include X-Content-Type-Options.",
            "remediation": "Set X-Content-Type-Options to nosniff.",
        },
        "x-frame-options": {
            "title": "Missing X-Frame-Options Header",
            "severity": "Low",
            "description": "The response does not include X-Frame-Options.",
            "remediation": "Configure X-Frame-Options or an equivalent CSP frame-ancestors policy.",
        },
        "referrer-policy": {
            "title": "Missing Referrer-Policy Header",
            "severity": "Low",
            "description": "The response does not include a Referrer-Policy header.",
            "remediation": "Configure an appropriate Referrer-Policy.",
        },
    }

    def run(self, target: Target) -> list[Finding]:
        http = HttpEngine()
        response = http.get(target.url)

        findings: list[Finding] = []

        for header_name, info in self.REQUIRED_HEADERS.items():
            if header_name not in response.headers:
                findings.append(
                    Finding(
                        title=info["title"],
                        severity=info["severity"],
                        confidence="High",
                        target=target.url,
                        endpoint=target.base_url,
                        description=info["description"],
                        evidence=f"HTTP {response.status_code} response is missing: {header_name}",
                        remediation=info["remediation"],
                    )
                )

        return findings
