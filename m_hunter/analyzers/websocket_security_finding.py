from m_hunter.analyzers.websocket_security import (
    WebSocketSecurityAnalysis,
    WebSocketSecurityIndicatorType,
)
from m_hunter.core.finding import Finding


class WebSocketSecurityFindingAnalyzer:
    name = "websocket_security_finding"

    _METADATA = {
        WebSocketSecurityIndicatorType.WEBSOCKET_SCHEME: {
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-319",
            "owasp": "A05:2021",
        },
        WebSocketSecurityIndicatorType.UPGRADE_HEADER: {
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-319",
            "owasp": "A05:2021",
        },
        WebSocketSecurityIndicatorType.CONNECTION_UPGRADE: {
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-319",
            "owasp": "A05:2021",
        },
        WebSocketSecurityIndicatorType.ORIGIN_HEADER: {
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-346",
            "owasp": "A07:2021",
        },
        WebSocketSecurityIndicatorType.MISSING_ORIGIN: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-346",
            "owasp": "A07:2021",
        },
        WebSocketSecurityIndicatorType.CORS_LIKE_ORIGIN: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-346",
            "owasp": "A07:2021",
        },
        WebSocketSecurityIndicatorType.SUBPROTOCOL: {
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-16",
            "owasp": "A05:2021",
        },
        WebSocketSecurityIndicatorType.AUTHENTICATION_CONTEXT: {
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-287",
            "owasp": "A07:2021",
        },
        WebSocketSecurityIndicatorType.SESSION_CONTEXT: {
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-384",
            "owasp": "A07:2021",
        },
        WebSocketSecurityIndicatorType.SENSITIVE_PATH: {
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-200",
            "owasp": "A01:2021",
        },
        WebSocketSecurityIndicatorType.WEBSOCKET_ERROR: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-209",
            "owasp": "A05:2021",
        },
    }

    def create_findings(
        self,
        analysis: WebSocketSecurityAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, WebSocketSecurityAnalysis):
            raise TypeError("analysis must be WebSocketSecurityAnalysis")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        findings: list[Finding] = []

        for indicator in analysis.indicators:
            metadata = self._METADATA[indicator.type]

            findings.append(
                Finding(
                    title=self._title_for(indicator.type),
                    severity=metadata["severity"],
                    confidence=metadata["confidence"],
                    target=target,
                    endpoint=endpoint,
                    parameter=indicator.name,
                    description=self._description_for(indicator.type),
                    evidence=indicator.evidence,
                    remediation=self._remediation_for(indicator.type),
                    cwe=metadata["cwe"],
                    owasp=metadata["owasp"],
                )
            )

        return findings

    def analyze(
        self,
        analysis: WebSocketSecurityAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        return self.create_findings(
            analysis,
            target,
            endpoint,
        )

    @staticmethod
    def _title_for(
        indicator_type: WebSocketSecurityIndicatorType,
    ) -> str:
        titles = {
            WebSocketSecurityIndicatorType.WEBSOCKET_SCHEME:
                "WebSocket Endpoint Detected",
            WebSocketSecurityIndicatorType.UPGRADE_HEADER:
                "WebSocket Upgrade Detected",
            WebSocketSecurityIndicatorType.CONNECTION_UPGRADE:
                "WebSocket Connection Upgrade Detected",
            WebSocketSecurityIndicatorType.ORIGIN_HEADER:
                "WebSocket Origin Header Detected",
            WebSocketSecurityIndicatorType.MISSING_ORIGIN:
                "WebSocket Origin Header Missing",
            WebSocketSecurityIndicatorType.CORS_LIKE_ORIGIN:
                "Broad WebSocket Origin Detected",
            WebSocketSecurityIndicatorType.SUBPROTOCOL:
                "WebSocket Subprotocol Detected",
            WebSocketSecurityIndicatorType.AUTHENTICATION_CONTEXT:
                "WebSocket Authentication Context Detected",
            WebSocketSecurityIndicatorType.SESSION_CONTEXT:
                "WebSocket Session Context Detected",
            WebSocketSecurityIndicatorType.SENSITIVE_PATH:
                "Sensitive WebSocket Path Detected",
            WebSocketSecurityIndicatorType.WEBSOCKET_ERROR:
                "WebSocket Error Information Detected",
        }

        return titles[indicator_type]

    @staticmethod
    def _description_for(
        indicator_type: WebSocketSecurityIndicatorType,
    ) -> str:
        if indicator_type == WebSocketSecurityIndicatorType.MISSING_ORIGIN:
            return (
                "A WebSocket context was observed without an Origin header. "
                "This may indicate that Origin-based access controls are "
                "not available, but the absence alone does not prove a "
                "cross-origin WebSocket vulnerability."
            )

        if indicator_type == WebSocketSecurityIndicatorType.CORS_LIKE_ORIGIN:
            return (
                "A broad or null Origin value was observed in a WebSocket "
                "context. Additional validation is required to determine "
                "whether the server incorrectly trusts the supplied origin."
            )

        if indicator_type == WebSocketSecurityIndicatorType.WEBSOCKET_ERROR:
            return (
                "A WebSocket-related error message was observed. Error "
                "information may reveal implementation details, but the "
                "indicator alone does not establish exploitable impact."
            )

        if indicator_type == WebSocketSecurityIndicatorType.SENSITIVE_PATH:
            return (
                "A potentially sensitive WebSocket path was detected. "
                "The path itself does not prove unauthorized access or "
                "information disclosure."
            )

        return (
            "A WebSocket security-related characteristic was detected. "
            "This indicator is informational unless controlled validation "
            "demonstrates a security impact."
        )

    @staticmethod
    def _remediation_for(
        indicator_type: WebSocketSecurityIndicatorType,
    ) -> str:
        if indicator_type in {
            WebSocketSecurityIndicatorType.MISSING_ORIGIN,
            WebSocketSecurityIndicatorType.CORS_LIKE_ORIGIN,
        }:
            return (
                "Validate the WebSocket Origin against an explicit allowlist "
                "when Origin-based protection is appropriate. Do not blindly "
                "trust arbitrary or null origins."
            )

        if indicator_type == WebSocketSecurityIndicatorType.WEBSOCKET_ERROR:
            return (
                "Avoid exposing unnecessary implementation details in "
                "WebSocket error responses. Return generic client-safe "
                "errors and keep detailed diagnostics server-side."
            )

        return (
            "Use wss:// for production WebSocket traffic, enforce "
            "authentication and authorization on WebSocket actions, "
            "validate message data, and apply explicit origin and "
            "session controls where appropriate."
        )
