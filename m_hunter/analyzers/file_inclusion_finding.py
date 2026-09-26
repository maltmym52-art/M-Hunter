from typing import Any

from m_hunter.analyzers.file_inclusion import (
    FileInclusionAnalysis,
    FileInclusionIndicator,
    FileInclusionIndicatorType,
)
from m_hunter.core.finding import Finding


class FileInclusionFindingAnalyzer:
    name = "file_inclusion_finding"

    _METADATA: dict[FileInclusionIndicatorType, dict[str, str]] = {
        FileInclusionIndicatorType.PATH_TRAVERSAL: {
            "severity": "High",
            "confidence": "Medium",
            "cwe": "CWE-22",
            "owasp": "A01:2021",
        },
        FileInclusionIndicatorType.WINDOWS_PATH_TRAVERSAL: {
            "severity": "High",
            "confidence": "Medium",
            "cwe": "CWE-22",
            "owasp": "A01:2021",
        },
        FileInclusionIndicatorType.ABSOLUTE_UNIX_PATH: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-22",
            "owasp": "A01:2021",
        },
        FileInclusionIndicatorType.ABSOLUTE_WINDOWS_PATH: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-22",
            "owasp": "A01:2021",
        },
        FileInclusionIndicatorType.FILE_SCHEME: {
            "severity": "High",
            "confidence": "Medium",
            "cwe": "CWE-98",
            "owasp": "A05:2021",
        },
        FileInclusionIndicatorType.PHP_WRAPPER: {
            "severity": "High",
            "confidence": "Medium",
            "cwe": "CWE-98",
            "owasp": "A05:2021",
        },
        FileInclusionIndicatorType.DATA_WRAPPER: {
            "severity": "High",
            "confidence": "Medium",
            "cwe": "CWE-98",
            "owasp": "A05:2021",
        },
        FileInclusionIndicatorType.HTTP_WRAPPER: {
            "severity": "Medium",
            "confidence": "Low",
            "cwe": "CWE-98",
            "owasp": "A05:2021",
        },
        FileInclusionIndicatorType.REMOTE_URL: {
            "severity": "Medium",
            "confidence": "Low",
            "cwe": "CWE-98",
            "owasp": "A05:2021",
        },
        FileInclusionIndicatorType.FILE_EXTENSION: {
            "severity": "Info",
            "confidence": "High",
            "cwe": "CWE-22",
            "owasp": "A01:2021",
        },
        FileInclusionIndicatorType.SENSITIVE_FILE: {
            "severity": "High",
            "confidence": "Medium",
            "cwe": "CWE-22",
            "owasp": "A01:2021",
        },
        FileInclusionIndicatorType.FILE_INCLUDE_ERROR: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-22",
            "owasp": "A05:2021",
        },
        FileInclusionIndicatorType.PHP_INCLUDE_ERROR: {
            "severity": "Medium",
            "confidence": "Medium",
            "cwe": "CWE-98",
            "owasp": "A05:2021",
        },
        FileInclusionIndicatorType.PATH_NOT_FOUND_ERROR: {
            "severity": "Low",
            "confidence": "Medium",
            "cwe": "CWE-22",
            "owasp": "A05:2021",
        },
    }

    def create_findings(
        self,
        analysis: FileInclusionAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for indicator in analysis.indicators:
            finding = self._create_finding(
                indicator,
                target=target,
                endpoint=endpoint,
                parameter=parameter,
            )
            findings.append(finding)

        return findings

    def _create_finding(
        self,
        indicator: FileInclusionIndicator,
        *,
        target: str,
        endpoint: str | None,
        parameter: str | None,
    ) -> Finding:
        metadata = self._METADATA[indicator.type]

        return Finding(
            title=self._title(indicator),
            severity=metadata["severity"],
            confidence=metadata["confidence"],
            target=target,
            endpoint=endpoint,
            parameter=parameter,
            description=self._description(indicator),
            evidence=f"{indicator.name}: {indicator.value}",
            remediation=(
                "Avoid using user-controlled input directly in file paths. "
                "Use an allowlist of permitted resources, canonicalize paths, "
                "restrict filesystem access, and reject traversal sequences "
                "and unsupported stream wrappers."
            ),
            cwe=metadata["cwe"],
            owasp=metadata["owasp"],
        )

    @staticmethod
    def _title(indicator: FileInclusionIndicator) -> str:
        titles = {
            FileInclusionIndicatorType.PATH_TRAVERSAL:
                "Potential Local File Inclusion / Path Traversal",
            FileInclusionIndicatorType.WINDOWS_PATH_TRAVERSAL:
                "Potential Windows Path Traversal",
            FileInclusionIndicatorType.ABSOLUTE_UNIX_PATH:
                "Absolute Unix File Path Indicator",
            FileInclusionIndicatorType.ABSOLUTE_WINDOWS_PATH:
                "Absolute Windows File Path Indicator",
            FileInclusionIndicatorType.FILE_SCHEME:
                "File URI Inclusion Indicator",
            FileInclusionIndicatorType.PHP_WRAPPER:
                "PHP Stream Wrapper Inclusion Indicator",
            FileInclusionIndicatorType.DATA_WRAPPER:
                "Data Stream Wrapper Inclusion Indicator",
            FileInclusionIndicatorType.HTTP_WRAPPER:
                "HTTP File Inclusion Indicator",
            FileInclusionIndicatorType.REMOTE_URL:
                "Potential Remote File Inclusion",
            FileInclusionIndicatorType.FILE_EXTENSION:
                "File Inclusion-Related Extension",
            FileInclusionIndicatorType.SENSITIVE_FILE:
                "Sensitive File Path Indicator",
            FileInclusionIndicatorType.FILE_INCLUDE_ERROR:
                "File Inclusion Error",
            FileInclusionIndicatorType.PHP_INCLUDE_ERROR:
                "PHP Include/Require Error",
            FileInclusionIndicatorType.PATH_NOT_FOUND_ERROR:
                "File Path Resolution Error",
        }

        return titles[indicator.type]

    @staticmethod
    def _description(indicator: FileInclusionIndicator) -> str:
        return (
            f"The response or analyzed request context contains an indicator "
            f"associated with file inclusion: {indicator.name}. "
            f"Observed value: {indicator.value}. "
            "This is an analytical indicator and does not by itself prove "
            "that local or remote file inclusion is exploitable."
        )

    def analyze(
        self,
        analysis: FileInclusionAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        return self.create_findings(
            analysis,
            target=target,
            endpoint=endpoint,
            parameter=parameter,
        )
