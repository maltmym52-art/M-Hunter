from dataclasses import dataclass

from m_hunter.analyzers.cors_advanced import (
    CORSAdvancedAnalysis,
    CORSAdvancedIndicatorType,
)


@dataclass(frozen=True)
class CORSAdvancedValidationResult:
    baseline_status: int
    candidate_status: int
    status_changed: bool
    content_changed: bool
    content_length_changed: bool
    headers_changed: bool
    response_changed: bool
    security_indicator_present: bool
    origin_reflection_present: bool
    credentials_present: bool
    potential_cors_issue: bool
    status: str
    evidence: str


class CORSAdvancedValidator:
    SECURITY_INDICATORS = {
        CORSAdvancedIndicatorType.REFLECTED_ARBITRARY_ORIGIN,
        CORSAdvancedIndicatorType.CREDENTIALED_ORIGIN_REFLECTION,
        CORSAdvancedIndicatorType.NULL_ORIGIN_REFLECTION,
        CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
        CORSAdvancedIndicatorType.PREFIX_TRUST,
        CORSAdvancedIndicatorType.SUFFIX_TRUST,
        CORSAdvancedIndicatorType.WILDCARD_CREDENTIALS,
    }

    REFLECTION_INDICATORS = {
        CORSAdvancedIndicatorType.ORIGIN_REFLECTION,
        CORSAdvancedIndicatorType.REFLECTED_ARBITRARY_ORIGIN,
        CORSAdvancedIndicatorType.CREDENTIALED_ORIGIN_REFLECTION,
        CORSAdvancedIndicatorType.NULL_ORIGIN_REFLECTION,
    }

    def validate(
        self,
        analysis: CORSAdvancedAnalysis,
        *,
        baseline_status: int,
        candidate_status: int,
        content_changed: bool = False,
        content_length_changed: bool = False,
        headers_changed: bool = False,
    ) -> CORSAdvancedValidationResult:
        if not isinstance(
            analysis,
            CORSAdvancedAnalysis,
        ):
            raise TypeError(
                "analysis must be an instance of "
                "CORSAdvancedAnalysis"
            )

        if not isinstance(baseline_status, int):
            raise TypeError(
                "baseline_status must be an integer"
            )

        if not isinstance(candidate_status, int):
            raise TypeError(
                "candidate_status must be an integer"
            )

        if not isinstance(content_changed, bool):
            raise TypeError(
                "content_changed must be a boolean"
            )

        if not isinstance(
            content_length_changed,
            bool,
        ):
            raise TypeError(
                "content_length_changed must be a boolean"
            )

        if not isinstance(headers_changed, bool):
            raise TypeError(
                "headers_changed must be a boolean"
            )

        status_changed = (
            baseline_status != candidate_status
        )

        response_changed = bool(
            status_changed
            or content_changed
            or content_length_changed
            or headers_changed
        )

        types = set(analysis.types)

        security_indicator_present = bool(
            types & self.SECURITY_INDICATORS
        )

        origin_reflection_present = bool(
            types & self.REFLECTION_INDICATORS
        )

        credentials_present = bool(
            types
            & {
                CORSAdvancedIndicatorType.CREDENTIALS_ENABLED,
                CORSAdvancedIndicatorType
                .CREDENTIALED_ORIGIN_REFLECTION,
                CORSAdvancedIndicatorType
                .WILDCARD_CREDENTIALS,
                CORSAdvancedIndicatorType
                .PREFLIGHT_CREDENTIALS,
            }
        )

        potential_cors_issue = bool(
            analysis.detected
            and security_indicator_present
            and (
                response_changed
                or origin_reflection_present
            )
        )

        if potential_cors_issue:
            status = "potential"
        elif analysis.detected:
            status = "indicator"
        else:
            status = "clean"

        evidence = (
            f"baseline_status={baseline_status}; "
            f"candidate_status={candidate_status}; "
            f"status_changed={status_changed}; "
            f"content_changed={content_changed}; "
            f"content_length_changed="
            f"{content_length_changed}; "
            f"headers_changed={headers_changed}; "
            f"response_changed={response_changed}; "
            f"security_indicator_present="
            f"{security_indicator_present}; "
            f"origin_reflection_present="
            f"{origin_reflection_present}; "
            f"credentials_present="
            f"{credentials_present}"
        )

        return CORSAdvancedValidationResult(
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            status_changed=status_changed,
            content_changed=content_changed,
            content_length_changed=content_length_changed,
            headers_changed=headers_changed,
            response_changed=response_changed,
            security_indicator_present=(
                security_indicator_present
            ),
            origin_reflection_present=(
                origin_reflection_present
            ),
            credentials_present=credentials_present,
            potential_cors_issue=(
                potential_cors_issue
            ),
            status=status,
            evidence=evidence,
        )
