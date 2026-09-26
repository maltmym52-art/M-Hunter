from dataclasses import dataclass, field
from enum import Enum

from m_hunter.core.response import HttpResponse


class CORSAdvancedIndicatorType(str, Enum):
    ORIGIN_REFLECTION = "origin_reflection"
    REFLECTED_ARBITRARY_ORIGIN = "reflected_arbitrary_origin"
    CREDENTIALED_ORIGIN_REFLECTION = "credentialed_origin_reflection"
    NULL_ORIGIN_REFLECTION = "null_origin_reflection"
    SUBDOMAIN_TRUST = "subdomain_trust"
    PREFIX_TRUST = "prefix_trust"
    SUFFIX_TRUST = "suffix_trust"
    WILDCARD_CREDENTIALS = "wildcard_credentials"
    CREDENTIALS_ENABLED = "credentials_enabled"
    VARY_ORIGIN_MISSING = "vary_origin_missing"
    ACCESS_CONTROL_ALLOW_ORIGIN_PRESENT = "allow_origin_present"
    ACCESS_CONTROL_ALLOW_CREDENTIALS_PRESENT = "allow_credentials_present"
    PREFLIGHT_ALLOWED = "preflight_allowed"
    PREFLIGHT_CREDENTIALS = "preflight_credentials"
    PREFLIGHT_METHODS = "preflight_methods"
    PREFLIGHT_HEADERS = "preflight_headers"


@dataclass(frozen=True)
class CORSAdvancedIndicator:
    type: CORSAdvancedIndicatorType
    evidence: str
    value: str | None = None


@dataclass
class CORSAdvancedAnalysis:
    detected: bool
    indicators: tuple[CORSAdvancedIndicator, ...] = field(
        default_factory=tuple
    )
    count: int = 0
    types: tuple[CORSAdvancedIndicatorType, ...] = field(
        default_factory=tuple
    )
    names: tuple[str, ...] = field(
        default_factory=tuple
    )

    @property
    def has_origin_reflection(self) -> bool:
        return any(
            indicator.type
            in {
                CORSAdvancedIndicatorType.ORIGIN_REFLECTION,
                CORSAdvancedIndicatorType.REFLECTED_ARBITRARY_ORIGIN,
                CORSAdvancedIndicatorType.CREDENTIALED_ORIGIN_REFLECTION,
                CORSAdvancedIndicatorType.NULL_ORIGIN_REFLECTION,
            }
            for indicator in self.indicators
        )

    def has_type(
        self,
        indicator_type: CORSAdvancedIndicatorType,
    ) -> bool:
        return indicator_type in self.types


class CORSAdvancedAnalyzer:
    """
    Advanced, response-comparison-oriented CORS analyzer.

    This analyzer does not claim that an explicit trusted origin is
    vulnerable merely because credentials are enabled. It looks for
    evidence that the supplied Origin is reflected or broadly trusted.
    """

    name = "cors_advanced"
    description = "Advanced CORS policy and origin reflection analyzer"

    _ORIGIN_HEADER = "origin"
    _ALLOW_ORIGIN = "access-control-allow-origin"
    _ALLOW_CREDENTIALS = "access-control-allow-credentials"
    _VARY = "vary"
    _ALLOW_METHODS = "access-control-allow-methods"
    _ALLOW_HEADERS = "access-control-allow-headers"

    def analyze(
        self,
        response: HttpResponse,
        *,
        origin: str | None = None,
        trusted_origin: str | None = None,
        candidate_origin: str | None = None,
        baseline: HttpResponse | None = None,
        preflight: bool = False,
    ) -> CORSAdvancedAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        if baseline is not None and not isinstance(
            baseline,
            HttpResponse,
        ):
            raise TypeError(
                "baseline must be an instance of HttpResponse or None"
            )

        values: list[CORSAdvancedIndicator] = []

        allow_origin = self._header(
            response,
            self._ALLOW_ORIGIN,
        )
        allow_credentials = self._header(
            response,
            self._ALLOW_CREDENTIALS,
        )
        vary = self._header(response, self._VARY)

        credentials_enabled = (
            allow_credentials is not None
            and allow_credentials.strip().lower() == "true"
        )

        if allow_origin is not None:
            values.append(
                CORSAdvancedIndicator(
                    type=(
                        CORSAdvancedIndicatorType
                        .ACCESS_CONTROL_ALLOW_ORIGIN_PRESENT
                    ),
                    evidence=(
                        "Access-Control-Allow-Origin is present."
                    ),
                    value=allow_origin,
                )
            )

        if allow_credentials:
            values.append(
                CORSAdvancedIndicator(
                    type=(
                        CORSAdvancedIndicatorType
                        .ACCESS_CONTROL_ALLOW_CREDENTIALS_PRESENT
                    ),
                    evidence=(
                        "Access-Control-Allow-Credentials is present."
                    ),
                    value=allow_credentials,
                )
            )

        if credentials_enabled:
            values.append(
                CORSAdvancedIndicator(
                    type=CORSAdvancedIndicatorType.CREDENTIALS_ENABLED,
                    evidence=(
                        "Access-Control-Allow-Credentials is true."
                    ),
                    value=allow_credentials,
                )
            )

        if (
            allow_origin is not None
            and allow_origin.strip() == "*"
            and credentials_enabled
        ):
            values.append(
                CORSAdvancedIndicator(
                    type=CORSAdvancedIndicatorType.WILDCARD_CREDENTIALS,
                    evidence=(
                        "Wildcard Access-Control-Allow-Origin is "
                        "combined with credentialed CORS."
                    ),
                    value=allow_origin,
                )
            )

        if origin and allow_origin:
            normalized_origin = origin.strip()
            normalized_allowed = allow_origin.strip()

            if normalized_allowed == normalized_origin:
                values.append(
                    CORSAdvancedIndicator(
                        type=CORSAdvancedIndicatorType.ORIGIN_REFLECTION,
                        evidence=(
                            "The supplied Origin is returned verbatim "
                            "by Access-Control-Allow-Origin."
                        ),
                        value=normalized_origin,
                    )
                )

                if credentials_enabled:
                    values.append(
                        CORSAdvancedIndicator(
                            type=(
                                CORSAdvancedIndicatorType
                                .CREDENTIALED_ORIGIN_REFLECTION
                            ),
                            evidence=(
                                "The supplied Origin is reflected while "
                                "credentials are enabled."
                            ),
                            value=normalized_origin,
                        )
                    )

                if normalized_origin.lower() == "null":
                    values.append(
                        CORSAdvancedIndicator(
                            type=(
                                CORSAdvancedIndicatorType
                                .NULL_ORIGIN_REFLECTION
                            ),
                            evidence=(
                                "The null Origin is reflected by the "
                                "CORS policy."
                            ),
                            value=normalized_origin,
                        )
                    )

            if normalized_allowed == "*" and candidate_origin:
                values.append(
                    CORSAdvancedIndicator(
                        type=(
                            CORSAdvancedIndicatorType
                            .REFLECTED_ARBITRARY_ORIGIN
                        ),
                        evidence=(
                            "The response uses a wildcard origin while "
                            "an arbitrary candidate Origin was supplied."
                        ),
                        value=candidate_origin,
                    )
                )

        if (
            baseline is not None
            and origin
            and allow_origin
        ):
            baseline_allow_origin = self._header(
                baseline,
                self._ALLOW_ORIGIN,
            )

            if (
                baseline_allow_origin is not None
                and baseline_allow_origin.strip() != allow_origin.strip()
                and allow_origin.strip() == origin.strip()
            ):
                values.append(
                    CORSAdvancedIndicator(
                        type=CORSAdvancedIndicatorType.ORIGIN_REFLECTION,
                        evidence=(
                            "Access-Control-Allow-Origin changed to "
                            "the supplied Origin between responses."
                        ),
                        value=origin.strip(),
                    )
                )

        if (
            origin
            and allow_origin
            and origin.strip() != allow_origin.strip()
            and self._looks_broadly_trusted(
                origin.strip(),
                allow_origin.strip(),
            )
        ):
            values.append(
                CORSAdvancedIndicator(
                    type=CORSAdvancedIndicatorType.SUBDOMAIN_TRUST,
                    evidence=(
                        "The allowed origin appears to broadly trust "
                        "the supplied origin."
                    ),
                    value=allow_origin,
                )
            )

        if (
            origin
            and allow_origin
            and origin.strip() != allow_origin.strip()
        ):
            if self._prefix_trust(
                origin.strip(),
                allow_origin.strip(),
            ):
                values.append(
                    CORSAdvancedIndicator(
                        type=CORSAdvancedIndicatorType.PREFIX_TRUST,
                        evidence=(
                            "The CORS origin policy appears to use "
                            "prefix-based trust."
                        ),
                        value=allow_origin,
                    )
                )

            if self._suffix_trust(
                origin.strip(),
                allow_origin.strip(),
            ):
                values.append(
                    CORSAdvancedIndicator(
                        type=CORSAdvancedIndicatorType.SUFFIX_TRUST,
                        evidence=(
                            "The CORS origin policy appears to use "
                            "suffix-based trust."
                        ),
                        value=allow_origin,
                    )
                )

        if (
            allow_origin is not None
            and origin is not None
            and self._origin_changes_without_vary(
                response,
                origin,
            )
        ):
            values.append(
                CORSAdvancedIndicator(
                    type=CORSAdvancedIndicatorType.VARY_ORIGIN_MISSING,
                    evidence=(
                        "The response varies by Origin but does not "
                        "advertise Origin through the Vary header."
                    ),
                    value=vary,
                )
            )

        if preflight:
            self._add_preflight_indicators(
                response,
                values,
            )

        unique_types = tuple(
            dict.fromkeys(indicator.type for indicator in values)
        )

        unique_names = tuple(
            indicator.type.value
            for indicator in values
        )

        return CORSAdvancedAnalysis(
            detected=bool(values),
            indicators=tuple(values),
            count=len(values),
            types=unique_types,
            names=unique_names,
        )

    @staticmethod
    def _header(
        response: HttpResponse,
        name: str,
    ) -> str | None:
        return response.get_header(name)

    @staticmethod
    def _origin_changes_without_vary(
        response: HttpResponse,
        origin: str,
    ) -> bool:
        vary = response.get_header("vary")

        if vary is None:
            return True

        values = {
            item.strip().lower()
            for item in vary.split(",")
            if item.strip()
        }

        return "*" not in values and "origin" not in values

    @staticmethod
    def _looks_broadly_trusted(
        supplied_origin: str,
        allowed_origin: str,
    ) -> bool:
        supplied = supplied_origin.lower()
        allowed = allowed_origin.lower()

        if allowed in {"*", "null"}:
            return True

        if "://" not in supplied or "://" not in allowed:
            return False

        supplied_host = supplied.split("://", 1)[1].split("/", 1)[0]
        allowed_host = allowed.split("://", 1)[1].split("/", 1)[0]

        if supplied_host == allowed_host:
            return False

        return (
            supplied_host.endswith("." + allowed_host)
            or allowed_host.endswith("." + supplied_host)
        )

    @staticmethod
    def _prefix_trust(
        supplied_origin: str,
        allowed_origin: str,
    ) -> bool:
        return (
            allowed_origin.endswith("*")
            and supplied_origin.startswith(
                allowed_origin[:-1]
            )
        )

    @staticmethod
    def _suffix_trust(
        supplied_origin: str,
        allowed_origin: str,
    ) -> bool:
        return (
            allowed_origin.startswith("*")
            and supplied_origin.endswith(
                allowed_origin[1:]
            )
        )

    def _add_preflight_indicators(
        self,
        response: HttpResponse,
        values: list[CORSAdvancedIndicator],
    ) -> None:
        allow_methods = self._header(
            response,
            self._ALLOW_METHODS,
        )

        allow_headers = self._header(
            response,
            self._ALLOW_HEADERS,
        )

        allow_credentials = self._header(
            response,
            self._ALLOW_CREDENTIALS,
        )

        if allow_methods:
            values.append(
                CORSAdvancedIndicator(
                    type=CORSAdvancedIndicatorType.PREFLIGHT_METHODS,
                    evidence=(
                        "Preflight response exposes "
                        "Access-Control-Allow-Methods."
                    ),
                    value=allow_methods,
                )
            )

        if allow_headers:
            values.append(
                CORSAdvancedIndicator(
                    type=CORSAdvancedIndicatorType.PREFLIGHT_HEADERS,
                    evidence=(
                        "Preflight response exposes "
                        "Access-Control-Allow-Headers."
                    ),
                    value=allow_headers,
                )
            )

        if allow_credentials:
            values.append(
                CORSAdvancedIndicator(
                    type=CORSAdvancedIndicatorType.PREFLIGHT_CREDENTIALS,
                    evidence=(
                        "Preflight response exposes "
                        "Access-Control-Allow-Credentials."
                    ),
                    value=allow_credentials,
                )
            )
