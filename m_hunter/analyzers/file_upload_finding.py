from m_hunter.analyzers.file_upload import (
    FileUploadAnalysis,
    FileUploadIndicatorType,
)
from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.core.finding import Finding


class FileUploadFindingAnalyzer(FindingAnalyzer):
    name = "file_upload_findings"
    description = "Converts file-upload indicators into findings"

    INDICATOR_METADATA = {
        FileUploadIndicatorType.DANGEROUS_EXTENSION: {
            "title": "Dangerous File Extension Accepted",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "The upload evidence contains a file extension "
                "commonly associated with executable or server-side "
                "content. This indicator requires further validation "
                "to determine whether the application stores, serves, "
                "or executes the uploaded file."
            ),
        },
        FileUploadIndicatorType.DOUBLE_EXTENSION: {
            "title": "Double File Extension Indicator",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The filename contains multiple extensions including "
                "a potentially dangerous extension. This may indicate "
                "an extension validation weakness and requires further "
                "validation."
            ),
        },
        FileUploadIndicatorType.MIME_MISMATCH: {
            "title": "File Extension and MIME Type Mismatch",
            "severity": "Low",
            "confidence": "Medium",
            "description": (
                "The supplied file extension does not match the "
                "observed MIME type. This can indicate weak upload "
                "validation but does not by itself prove exploitation."
            ),
        },
        FileUploadIndicatorType.DANGEROUS_MIME: {
            "title": "Dangerous Upload MIME Type",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "The upload evidence contains a MIME type commonly "
                "associated with executable or server-side content. "
                "Further validation is required."
            ),
        },
        FileUploadIndicatorType.EXECUTABLE_CONTENT_TYPE: {
            "title": "Executable Upload Content-Type",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "The upload request uses a Content-Type associated "
                "with executable content. This is an indicator of "
                "potentially unsafe upload handling."
            ),
        },
        FileUploadIndicatorType.UNSAFE_FILENAME: {
            "title": "Unsafe Upload Filename",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "The upload filename contains path-related or unsafe "
                "filename patterns. Further validation is required "
                "to determine whether the server uses the filename "
                "unsafely."
            ),
        },
    }

    REMEDIATION = (
        "Allowlist permitted file extensions and MIME types, "
        "validate file content independently of user-controlled "
        "metadata, normalize filenames, reject path separators, "
        "store uploads outside executable web roots, and prevent "
        "uploaded content from being interpreted as executable code."
    )

    def analyze(
        self,
        analysis: FileUploadAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, FileUploadAnalysis):
            raise TypeError(
                "analysis must be a FileUploadAnalysis"
            )

        if not analysis.detected:
            return []

        findings: list[Finding] = []

        for indicator_type in analysis.types:
            metadata = self.INDICATOR_METADATA.get(
                indicator_type,
                {
                    "title": "File Upload Security Indicator",
                    "severity": "Low",
                    "confidence": "Low",
                    "description": (
                        "A file-upload security indicator was "
                        "detected and requires further validation."
                    ),
                },
            )

            indicators = [
                indicator
                for indicator in analysis.indicators
                if indicator.type == indicator_type
            ]

            indicator_name = (
                indicator_type.value
                if isinstance(indicator_type, FileUploadIndicatorType)
                else str(indicator_type)
            )

            evidence = [
                f"indicator type: {indicator_name}",
                f"indicator count: {len(indicators)}",
            ]

            for indicator in indicators:
                evidence.append(
                    f"evidence: {indicator.evidence}"
                )

            findings.append(
                self.create_finding(
                    title=metadata["title"],
                    severity=metadata["severity"],
                    confidence=metadata["confidence"],
                    target=target,
                    endpoint=endpoint,
                    parameter=parameter,
                    description=metadata["description"],
                    evidence="; ".join(evidence),
                    remediation=self.REMEDIATION,
                    cwe="CWE-434",
                    owasp="A04:2021",
                )
            )

        return findings
