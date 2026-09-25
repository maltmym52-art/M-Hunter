from dataclasses import dataclass

from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class ResponseComparison:
    status_code_changed: bool
    status_category_changed: bool
    content_length_changed: bool
    content_changed: bool
    headers_changed: bool
    cookies_changed: bool

    @property
    def behavior_changed(self) -> bool:
        return (
            self.status_code_changed
            or self.status_category_changed
            or self.content_length_changed
            or self.content_changed
            or self.headers_changed
            or self.cookies_changed
        )

    @property
    def difference_count(self) -> int:
        return sum(
            (
                self.status_code_changed,
                self.status_category_changed,
                self.content_length_changed,
                self.content_changed,
                self.headers_changed,
                self.cookies_changed,
            )
        )


class ResponseComparator:
    def compare(
        self,
        baseline: HttpResponse,
        candidate: HttpResponse,
    ) -> ResponseComparison:
        if not isinstance(baseline, HttpResponse):
            raise TypeError(
                "baseline must be an instance of HttpResponse"
            )

        if not isinstance(candidate, HttpResponse):
            raise TypeError(
                "candidate must be an instance of HttpResponse"
            )

        return ResponseComparison(
            status_code_changed=(
                baseline.status_code
                != candidate.status_code
            ),
            status_category_changed=(
                baseline.status_category
                != candidate.status_category
            ),
            content_length_changed=(
                baseline.content_length
                != candidate.content_length
            ),
            content_changed=(
                baseline.content
                != candidate.content
            ),
            headers_changed=(
                baseline.headers
                != candidate.headers
            ),
            cookies_changed=(
                baseline.cookies
                != candidate.cookies
            ),
        )


@dataclass(frozen=True)
class AuthorizationValidationResult:
    comparison: ResponseComparison
    resource_changed: bool
    identity_changed: bool
    authorization_context_changed: bool
    evidence: tuple[str, ...]

    @property
    def behavior_changed(self) -> bool:
        return self.comparison.behavior_changed

    @property
    def potentially_authorization_relevant(self) -> bool:
        return (
            self.behavior_changed
            and (
                self.resource_changed
                or self.identity_changed
                or self.authorization_context_changed
            )
        )


class AuthorizationValidator:
    """
    Compares authorized-request scenarios.

    A behavioral difference is evidence for further validation,
    not proof of IDOR/BOLA by itself.
    """

    def __init__(
        self,
        comparator: ResponseComparator | None = None,
    ):
        self.comparator = (
            comparator
            if comparator is not None
            else ResponseComparator()
        )

    def validate(
        self,
        *,
        baseline: HttpResponse,
        candidate: HttpResponse,
        resource_changed: bool = False,
        identity_changed: bool = False,
        authorization_context_changed: bool = False,
    ) -> AuthorizationValidationResult:
        comparison = self.comparator.compare(
            baseline,
            candidate,
        )

        evidence: list[str] = []

        if comparison.status_code_changed:
            evidence.append(
                "HTTP status code changed."
            )

        if comparison.status_category_changed:
            evidence.append(
                "HTTP status category changed."
            )

        if comparison.content_length_changed:
            evidence.append(
                "Response content length changed."
            )

        if comparison.content_changed:
            evidence.append(
                "Response content changed."
            )

        if comparison.headers_changed:
            evidence.append(
                "Response headers changed."
            )

        if comparison.cookies_changed:
            evidence.append(
                "Response cookies changed."
            )

        return AuthorizationValidationResult(
            comparison=comparison,
            resource_changed=resource_changed,
            identity_changed=identity_changed,
            authorization_context_changed=(
                authorization_context_changed
            ),
            evidence=tuple(evidence),
        )
