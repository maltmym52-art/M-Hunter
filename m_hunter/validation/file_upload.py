from dataclasses import dataclass, field

from m_hunter.analyzers.file_upload import FileUploadAnalysis
from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class FileUploadValidationResult:
    baseline: HttpResponse
    candidate: HttpResponse
    analysis: FileUploadAnalysis
    response_changed: bool
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    upload_behavior_changed: bool
    potential_upload_issue: bool
    evidence: tuple[str, ...] = field(default_factory=tuple)

    @property
    def status(self) -> str:
        if self.potential_upload_issue:
            return "potential_upload_issue"

        if self.analysis.detected:
            return "indicator_detected"

        return "no_indicator"


class FileUploadValidator:
    """
    Validates file-upload indicators using controlled baseline and
    candidate response comparison.

    This validator does not upload files, execute files, or perform
    active exploitation.
    """

    def validate(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
        analysis: FileUploadAnalysis,
    ) -> FileUploadValidationResult:
        if not isinstance(baseline, HttpResponse):
            raise TypeError("baseline must be an HttpResponse")

        if not isinstance(candidate, HttpResponse):
            raise TypeError("candidate must be an HttpResponse")

        if not isinstance(analysis, FileUploadAnalysis):
            raise TypeError(
                "analysis must be a FileUploadAnalysis"
            )

        evidence: list[str] = []

        status_changed = (
            baseline.status_code != candidate.status_code
        )

        content_changed = (
            baseline.content != candidate.content
        )

        content_length_changed = (
            baseline.content_length
            != candidate.content_length
        )

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
        )

        upload_behavior_changed = response_changed

        if status_changed:
            evidence.append(
                f"status changed: "
                f"{baseline.status_code} -> "
                f"{candidate.status_code}"
            )

        if content_changed:
            evidence.append(
                "response content changed"
            )

        if content_length_changed:
            evidence.append(
                f"content length changed: "
                f"{baseline.content_length} -> "
                f"{candidate.content_length}"
            )

        if analysis.detected:
            evidence.append(
                f"file-upload indicators detected: "
                f"{analysis.indicator_count}"
            )

            for indicator_type in analysis.types:
                indicator_name = (
                    indicator_type.value
                    if hasattr(indicator_type, "value")
                    else str(indicator_type)
                )

                evidence.append(
                    f"indicator type: {indicator_name}"
                )

        potential_upload_issue = (
            analysis.detected
            and upload_behavior_changed
        )

        if potential_upload_issue:
            evidence.append(
                "file-upload indicator and response behavior "
                "changed together"
            )

        return FileUploadValidationResult(
            baseline=baseline,
            candidate=candidate,
            analysis=analysis,
            response_changed=response_changed,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            upload_behavior_changed=upload_behavior_changed,
            potential_upload_issue=potential_upload_issue,
            evidence=tuple(evidence),
        )
