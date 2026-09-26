from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.idor import (
    IDORAnalysis,
    IDORIndicatorType,
)
from m_hunter.core.finding import Finding


class IDORFindingAnalyzer(FindingAnalyzer):
    name = "idor_findings"
    description = "Converts IDOR/BOLA analysis into findings"

    METADATA = {
        IDORIndicatorType.RESOURCE_PARAMETER: (
            "Potential IDOR/BOLA resource parameter",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.RESOURCE_PATH: (
            "Potential IDOR/BOLA resource path",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.USER_IDENTIFIER: (
            "User-controlled resource identifier",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.ACCOUNT_IDENTIFIER: (
            "Account resource identifier",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.OBJECT_IDENTIFIER: (
            "Object resource identifier",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.DOCUMENT_IDENTIFIER: (
            "Document resource identifier",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.FILE_IDENTIFIER: (
            "File resource identifier",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.ORDER_IDENTIFIER: (
            "Order resource identifier",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.INVOICE_IDENTIFIER: (
            "Invoice resource identifier",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.PROJECT_IDENTIFIER: (
            "Project resource identifier",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.AUTHENTICATION_CONTEXT: (
            "Authenticated authorization context",
            "Info",
            "High",
            "CWE-862",
            "A01:2021",
        ),
        IDORIndicatorType.SESSION_CONTEXT: (
            "Session-based authorization context",
            "Info",
            "High",
            "CWE-862",
            "A01:2021",
        ),
        IDORIndicatorType.API_RESOURCE: (
            "API resource suitable for authorization testing",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.NUMERIC_IDENTIFIER: (
            "Numeric resource identifier",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
        IDORIndicatorType.UUID_IDENTIFIER: (
            "UUID resource identifier",
            "Info",
            "High",
            "CWE-639",
            "A01:2021",
        ),
    }

    def analyze(
        self,
        analysis: IDORAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, IDORAnalysis):
            raise TypeError(
                "analysis must be an IDORAnalysis"
            )

        findings: list[Finding] = []

        for indicator in analysis.indicators:
            metadata = self.METADATA.get(indicator.type)

            if metadata is None:
                continue

            (
                title,
                severity,
                confidence,
                cwe,
                owasp,
            ) = metadata

            value_text = (
                f" Indicator: {indicator.value}."
                if indicator.value is not None
                else ""
            )

            findings.append(
                self.create_finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    parameter=parameter,
                    description=(
                        "The request contains an identifier or "
                        "authorization context that may be relevant "
                        "to IDOR/BOLA testing."
                        " This indicator does not prove that "
                        "unauthorized access is possible."
                    ),
                    evidence=(
                        f"Detected IDOR/BOLA indicator "
                        f"'{indicator.type.value}'."
                        f"{value_text}"
                    ),
                    remediation=(
                        "Enforce server-side object-level "
                        "authorization for every requested resource "
                        "and verify that the authenticated principal "
                        "is permitted to access the referenced object."
                    ),
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
