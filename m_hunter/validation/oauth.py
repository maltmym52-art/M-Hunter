from dataclasses import dataclass

from m_hunter.analyzers.oauth import OAuthAnalysis


@dataclass(frozen=True)
class OAuthValidationResult:
    baseline_status: int | None
    candidate_status: int | None
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    behavior_changed: bool
    potential_oauth_issue: bool
    status: str
    evidence: tuple[str, ...]


class OAuthValidator:
    """Validates OAuth behavior through controlled baseline/candidate comparison."""

    def validate(
        self,
        analysis: OAuthAnalysis,
        *,
        baseline_status: int | None = None,
        candidate_status: int | None = None,
        baseline_content: str | bytes | None = None,
        candidate_content: str | bytes | None = None,
        baseline_headers: dict[str, str] | None = None,
        candidate_headers: dict[str, str] | None = None,
        behavior_changed: bool = False,
    ) -> OAuthValidationResult:
        if not isinstance(analysis, OAuthAnalysis):
            raise TypeError(
                "analysis must be an OAuthAnalysis"
            )

        if baseline_headers is not None and not isinstance(
            baseline_headers,
            dict,
        ):
            raise TypeError(
                "baseline_headers must be a dictionary or None"
            )

        if candidate_headers is not None and not isinstance(
            candidate_headers,
            dict,
        ):
            raise TypeError(
                "candidate_headers must be a dictionary or None"
            )

        if not isinstance(behavior_changed, bool):
            raise TypeError(
                "behavior_changed must be a boolean"
            )

        status_changed = (
            baseline_status is not None
            and candidate_status is not None
            and baseline_status != candidate_status
        )

        content_changed = (
            baseline_content is not None
            and candidate_content is not None
            and baseline_content != candidate_content
        )

        baseline_length = (
            len(baseline_content)
            if baseline_content is not None
            else None
        )
        candidate_length = (
            len(candidate_content)
            if candidate_content is not None
            else None
        )

        content_length_changed = (
            baseline_length is not None
            and candidate_length is not None
            and baseline_length != candidate_length
        )

        normalized_baseline_headers = {
            str(key).lower(): str(value)
            for key, value in (baseline_headers or {}).items()
        }

        normalized_candidate_headers = {
            str(key).lower(): str(value)
            for key, value in (candidate_headers or {}).items()
        }

        headers_changed = (
            bool(baseline_headers or candidate_headers)
            and normalized_baseline_headers
            != normalized_candidate_headers
        )

        response_changed = (
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        potential_oauth_issue = (
            analysis.detected
            and (
                response_changed
                or behavior_changed
            )
        )

        evidence: list[str] = []

        if status_changed:
            evidence.append(
                "OAuth baseline and candidate status codes differ."
            )

        if content_changed:
            evidence.append(
                "OAuth baseline and candidate response content differ."
            )

        if content_length_changed:
            evidence.append(
                "OAuth baseline and candidate content lengths differ."
            )

        if headers_changed:
            evidence.append(
                "OAuth baseline and candidate response headers differ."
            )

        if behavior_changed:
            evidence.append(
                "OAuth behavior changed during controlled validation."
            )

        if analysis.detected:
            evidence.append(
                "OAuth security indicators were detected by analysis."
            )

        if potential_oauth_issue:
            status = "potential_oauth_issue"
        elif behavior_changed:
            status = "behavior_changed"
        elif analysis.detected:
            status = "indicator_detected"
        else:
            status = "no_indicator"

        return OAuthValidationResult(
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            behavior_changed=behavior_changed,
            potential_oauth_issue=potential_oauth_issue,
            status=status,
            evidence=tuple(evidence),
        )
