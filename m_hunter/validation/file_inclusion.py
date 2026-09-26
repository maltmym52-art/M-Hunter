from dataclasses import dataclass

from m_hunter.analyzers.file_inclusion import (
    FileInclusionAnalysis,
    FileInclusionIndicatorType,
)


@dataclass(frozen=True)
class FileInclusionValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    behavior_changed: bool
    security_indicator_present: bool
    potential_file_inclusion: bool
    status: str
    evidence: str


class FileInclusionValidator:
    SECURITY_RELEVANT_TYPES = {
        FileInclusionIndicatorType.PATH_TRAVERSAL,
        FileInclusionIndicatorType.WINDOWS_PATH_TRAVERSAL,
        FileInclusionIndicatorType.FILE_SCHEME,
        FileInclusionIndicatorType.PHP_WRAPPER,
        FileInclusionIndicatorType.DATA_WRAPPER,
        FileInclusionIndicatorType.HTTP_WRAPPER,
        FileInclusionIndicatorType.REMOTE_URL,
        FileInclusionIndicatorType.SENSITIVE_FILE,
        FileInclusionIndicatorType.FILE_INCLUDE_ERROR,
        FileInclusionIndicatorType.PHP_INCLUDE_ERROR,
    }

    def validate(
        self,
        baseline_status: int,
        candidate_status: int,
        *,
        baseline_content: str = "",
        candidate_content: str = "",
        baseline_headers: dict[str, str] | None = None,
        candidate_headers: dict[str, str] | None = None,
        analysis: FileInclusionAnalysis | None = None,
    ) -> FileInclusionValidationResult:
        baseline_headers = baseline_headers or {}
        candidate_headers = candidate_headers or {}

        status_changed = baseline_status != candidate_status
        content_changed = baseline_content != candidate_content
        content_length_changed = (
            len(baseline_content) != len(candidate_content)
        )
        headers_changed = baseline_headers != candidate_headers

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        behavior_changed = response_changed

        security_indicator_present = bool(
            analysis
            and any(
                indicator.type in self.SECURITY_RELEVANT_TYPES
                for indicator in analysis.indicators
            )
        )

        potential_file_inclusion = bool(
            analysis
            and analysis.detected
            and security_indicator_present
            and behavior_changed
        )

        if potential_file_inclusion:
            status = "potential"
        elif analysis and analysis.detected:
            status = "indicator"
        else:
            status = "clean"

        evidence_parts: list[str] = []

        if status_changed:
            evidence_parts.append(
                f"status changed {baseline_status}->{candidate_status}"
            )

        if content_changed:
            evidence_parts.append("response content changed")

        if content_length_changed:
            evidence_parts.append("response length changed")

        if headers_changed:
            evidence_parts.append("response headers changed")

        if security_indicator_present:
            evidence_parts.append("file inclusion security indicator present")

        if not evidence_parts:
            evidence_parts.append("no relevant file inclusion behavior observed")

        return FileInclusionValidationResult(
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            behavior_changed=behavior_changed,
            security_indicator_present=security_indicator_present,
            potential_file_inclusion=potential_file_inclusion,
            status=status,
            evidence="; ".join(evidence_parts),
        )
