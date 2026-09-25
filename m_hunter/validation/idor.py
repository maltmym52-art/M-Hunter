from dataclasses import dataclass

from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.validation.authorization import (
    AuthorizationValidationResult,
    AuthorizationValidator,
)


@dataclass(frozen=True)
class IDORCandidate:
    parameter: str
    original_value: str
    candidate_value: str


@dataclass(frozen=True)
class IDORValidationResult:
    candidate: IDORCandidate
    authorization_result: AuthorizationValidationResult

    @property
    def behavior_changed(self) -> bool:
        return self.authorization_result.behavior_changed

    @property
    def potentially_accessible(self) -> bool:
        return (
            self.authorization_result
            .potentially_authorization_relevant
        )


class IDORValidator:
    """
    Prepares and evaluates controlled IDOR/BOLA comparisons.

    A changed response is evidence for further investigation and
    is not treated as proof of unauthorized access by itself.
    """

    def __init__(
        self,
        authorization_validator: AuthorizationValidator | None = None,
    ):
        self.authorization_validator = (
            authorization_validator
            if authorization_validator is not None
            else AuthorizationValidator()
        )

    def build_candidate_request(
        self,
        request: HttpRequest,
        *,
        parameter: str,
        candidate_value: str,
    ) -> HttpRequest:
        if not isinstance(request, HttpRequest):
            raise TypeError(
                "request must be an instance of HttpRequest"
            )

        if not parameter.strip():
            raise ValueError(
                "parameter must not be empty"
            )

        copied = request.copy()

        if parameter not in copied.params:
            raise KeyError(
                f"parameter not found: {parameter}"
            )

        copied.params[parameter] = candidate_value

        return copied

    def validate(
        self,
        *,
        baseline_request: HttpRequest,
        baseline_response: HttpResponse,
        candidate_request: HttpRequest,
        candidate_response: HttpResponse,
        parameter: str,
        original_value: str,
        candidate_value: str,
        identity_changed: bool = False,
        authorization_context_changed: bool = False,
    ) -> IDORValidationResult:
        if not isinstance(
            baseline_request,
            HttpRequest,
        ):
            raise TypeError(
                "baseline_request must be an instance of HttpRequest"
            )

        if not isinstance(
            candidate_request,
            HttpRequest,
        ):
            raise TypeError(
                "candidate_request must be an instance of HttpRequest"
            )

        if baseline_request.full_url == candidate_request.full_url:
            raise ValueError(
                "candidate request must differ from baseline request"
            )

        candidate = IDORCandidate(
            parameter=parameter,
            original_value=original_value,
            candidate_value=candidate_value,
        )

        authorization_result = (
            self.authorization_validator.validate(
                baseline=baseline_response,
                candidate=candidate_response,
                resource_changed=True,
                identity_changed=identity_changed,
                authorization_context_changed=(
                    authorization_context_changed
                ),
            )
        )

        return IDORValidationResult(
            candidate=candidate,
            authorization_result=authorization_result,
        )
