from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import parse_qs, urlparse


class SAMLIndicatorType(str, Enum):
    SAML_RESPONSE = "saml_response"
    RELAY_STATE = "relay_state"
    ISSUER = "issuer"
    AUDIENCE = "audience"
    DESTINATION = "destination"
    ACS_URL = "acs_url"
    SIGNATURE = "signature"
    SIGNATURE_ALGORITHM = "signature_algorithm"
    ASSERTION = "assertion"
    NAME_ID = "name_id"
    NOT_BEFORE = "not_before"
    NOT_ON_OR_AFTER = "not_on_or_after"
    IN_RESPONSE_TO = "in_response_to"
    ENCRYPTION = "encryption"
    UNSIGNED_ASSERTION = "unsigned_assertion"
    WEAK_SIGNATURE_ALGORITHM = "weak_signature_algorithm"


@dataclass(frozen=True)
class SAMLIndicator:
    type: SAMLIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class SAMLAnalysis:
    detected: bool
    count: int
    types: tuple[SAMLIndicatorType, ...]
    names: tuple[str, ...]
    indicators: tuple[SAMLIndicator, ...]

    @property
    def has_saml_response(self) -> bool:
        return SAMLIndicatorType.SAML_RESPONSE in self.types

    @property
    def has_relay_state(self) -> bool:
        return SAMLIndicatorType.RELAY_STATE in self.types

    @property
    def has_issuer(self) -> bool:
        return SAMLIndicatorType.ISSUER in self.types

    @property
    def has_audience(self) -> bool:
        return SAMLIndicatorType.AUDIENCE in self.types

    @property
    def has_destination(self) -> bool:
        return SAMLIndicatorType.DESTINATION in self.types

    @property
    def has_acs_url(self) -> bool:
        return SAMLIndicatorType.ACS_URL in self.types

    @property
    def has_signature(self) -> bool:
        return SAMLIndicatorType.SIGNATURE in self.types

    @property
    def has_signature_algorithm(self) -> bool:
        return SAMLIndicatorType.SIGNATURE_ALGORITHM in self.types

    @property
    def has_assertion(self) -> bool:
        return SAMLIndicatorType.ASSERTION in self.types

    @property
    def has_name_id(self) -> bool:
        return SAMLIndicatorType.NAME_ID in self.types

    @property
    def has_not_before(self) -> bool:
        return SAMLIndicatorType.NOT_BEFORE in self.types

    @property
    def has_not_on_or_after(self) -> bool:
        return SAMLIndicatorType.NOT_ON_OR_AFTER in self.types

    @property
    def has_in_response_to(self) -> bool:
        return SAMLIndicatorType.IN_RESPONSE_TO in self.types

    @property
    def has_encryption(self) -> bool:
        return SAMLIndicatorType.ENCRYPTION in self.types

    @property
    def has_unsigned_assertion(self) -> bool:
        return SAMLIndicatorType.UNSIGNED_ASSERTION in self.types

    @property
    def has_weak_signature_algorithm(self) -> bool:
        return SAMLIndicatorType.WEAK_SIGNATURE_ALGORITHM in self.types


class SAMLAnalyzer:
    """Analyzes SAML request/response indicators without exploitation."""

    SAML_KEYS = {
        "samlresponse",
        "samlrequest",
        "relaystate",
        "issuer",
        "audience",
        "destination",
        "acs",
        "acs_url",
        "signature",
        "sigalg",
        "signature_algorithm",
        "assertion",
        "nameid",
        "notbefore",
        "notonorafter",
        "inresponseto",
        "encryption",
    }

    WEAK_SIGNATURE_ALGORITHMS = {
        "rsa-sha1",
        "dsa-sha1",
        "sha1",
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
    }

    def analyze(
        self,
        url: str | None = None,
        *,
        params: dict[str, Any] | None = None,
        body: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        saml_response: str | None = None,
        relay_state: str | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        destination: str | None = None,
        acs_url: str | None = None,
        signature: str | None = None,
        signature_algorithm: str | None = None,
        assertion: str | None = None,
        name_id: str | None = None,
        not_before: str | None = None,
        not_on_or_after: str | None = None,
        in_response_to: str | None = None,
        encryption: str | None = None,
        signed_assertion: bool | None = None,
    ) -> SAMLAnalysis:
        if url is not None and not isinstance(url, str):
            raise TypeError("url must be a string or None")

        if params is not None and not isinstance(params, dict):
            raise TypeError("params must be a dictionary or None")

        if body is not None and not isinstance(body, (str, bytes)):
            raise TypeError("body must be a string, bytes, or None")

        if headers is not None and not isinstance(headers, dict):
            raise TypeError("headers must be a dictionary or None")

        params = params.copy() if params else {}
        headers = headers.copy() if headers else {}

        indicators: list[SAMLIndicator] = []

        def add(
            indicator_type: SAMLIndicatorType,
            evidence: str,
            name: str | None = None,
            value: str | None = None,
        ) -> None:
            indicators.append(
                SAMLIndicator(
                    type=indicator_type,
                    evidence=evidence,
                    name=name,
                    value=value,
                )
            )

        parsed_url = urlparse(url) if url else None

        if parsed_url:
            query_params = parse_qs(
                parsed_url.query,
                keep_blank_values=True,
            )

            for key, values in query_params.items():
                if key not in params:
                    params[key] = values[-1] if values else ""

        normalized = {
            str(key).lower().replace("-", "_"): str(value)
            for key, value in params.items()
        }

        body_text = (
            body.decode("utf-8", errors="replace")
            if isinstance(body, bytes)
            else (body or "")
        )

        combined_text = (
            " ".join(
                [
                    body_text,
                    " ".join(
                        f"{key}={value}"
                        for key, value in normalized.items()
                    ),
                ]
            )
        )

        def first_value(*keys: str) -> str | None:
            for key in keys:
                normalized_key = key.lower().replace("-", "_")
                if normalized_key in normalized:
                    return normalized[normalized_key]
            return None

        effective_saml_response = (
            saml_response
            or first_value("samlresponse", "saml_response")
        )
        effective_relay_state = (
            relay_state
            or first_value("relaystate", "relay_state")
        )
        effective_issuer = issuer or first_value("issuer")
        effective_audience = audience or first_value("audience")
        effective_destination = (
            destination
            or first_value("destination")
        )
        effective_acs_url = (
            acs_url
            or first_value("acs", "acs_url")
        )
        effective_signature = (
            signature
            or first_value("signature")
        )
        effective_signature_algorithm = (
            signature_algorithm
            or first_value(
                "sigalg",
                "signature_algorithm",
            )
        )
        effective_assertion = (
            assertion
            or first_value("assertion")
        )
        effective_name_id = (
            name_id
            or first_value("nameid", "name_id")
        )
        effective_not_before = (
            not_before
            or first_value("notbefore", "not_before")
        )
        effective_not_on_or_after = (
            not_on_or_after
            or first_value(
                "notonorafter",
                "not_on_or_after",
            )
        )
        effective_in_response_to = (
            in_response_to
            or first_value(
                "inresponseto",
                "in_response_to",
            )
        )
        effective_encryption = (
            encryption
            or first_value("encryption")
        )

        if effective_saml_response is not None:
            add(
                SAMLIndicatorType.SAML_RESPONSE,
                "SAMLResponse parameter detected.",
                name="SAMLResponse",
                value=effective_saml_response,
            )

        if effective_relay_state is not None:
            add(
                SAMLIndicatorType.RELAY_STATE,
                "RelayState parameter detected.",
                name="RelayState",
                value=effective_relay_state,
            )

        if effective_issuer is not None:
            add(
                SAMLIndicatorType.ISSUER,
                "SAML Issuer detected.",
                name="Issuer",
                value=effective_issuer,
            )

        if effective_audience is not None:
            add(
                SAMLIndicatorType.AUDIENCE,
                "SAML Audience detected.",
                name="Audience",
                value=effective_audience,
            )

        if effective_destination is not None:
            add(
                SAMLIndicatorType.DESTINATION,
                "SAML Destination detected.",
                name="Destination",
                value=effective_destination,
            )

        if effective_acs_url is not None:
            add(
                SAMLIndicatorType.ACS_URL,
                "SAML ACS URL detected.",
                name="ACS",
                value=effective_acs_url,
            )

        if effective_signature is not None:
            add(
                SAMLIndicatorType.SIGNATURE,
                "SAML signature detected.",
                name="Signature",
                value=effective_signature,
            )

        if effective_signature_algorithm is not None:
            add(
                SAMLIndicatorType.SIGNATURE_ALGORITHM,
                "SAML signature algorithm detected.",
                name="SignatureAlgorithm",
                value=effective_signature_algorithm,
            )

            if (
                effective_signature_algorithm.lower()
                in self.WEAK_SIGNATURE_ALGORITHMS
            ):
                add(
                    SAMLIndicatorType.WEAK_SIGNATURE_ALGORITHM,
                    "Weak SAML signature algorithm detected.",
                    name="SignatureAlgorithm",
                    value=effective_signature_algorithm,
                )

        if effective_assertion is not None:
            add(
                SAMLIndicatorType.ASSERTION,
                "SAML assertion detected.",
                name="Assertion",
                value=effective_assertion,
            )

        if effective_name_id is not None:
            add(
                SAMLIndicatorType.NAME_ID,
                "SAML NameID detected.",
                name="NameID",
                value=effective_name_id,
            )

        if effective_not_before is not None:
            add(
                SAMLIndicatorType.NOT_BEFORE,
                "SAML NotBefore condition detected.",
                name="NotBefore",
                value=effective_not_before,
            )

        if effective_not_on_or_after is not None:
            add(
                SAMLIndicatorType.NOT_ON_OR_AFTER,
                "SAML NotOnOrAfter condition detected.",
                name="NotOnOrAfter",
                value=effective_not_on_or_after,
            )

        if effective_in_response_to is not None:
            add(
                SAMLIndicatorType.IN_RESPONSE_TO,
                "SAML InResponseTo value detected.",
                name="InResponseTo",
                value=effective_in_response_to,
            )

        if effective_encryption is not None:
            add(
                SAMLIndicatorType.ENCRYPTION,
                "SAML encryption indicator detected.",
                name="Encryption",
                value=effective_encryption,
            )

        if (
            signed_assertion is False
            and effective_assertion is not None
        ):
            add(
                SAMLIndicatorType.UNSIGNED_ASSERTION,
                "SAML assertion is explicitly marked as unsigned.",
                name="Assertion",
                value=effective_assertion,
            )

        if (
            signed_assertion is None
            and effective_assertion is not None
            and "signature" not in combined_text.lower()
        ):
            add(
                SAMLIndicatorType.UNSIGNED_ASSERTION,
                "SAML assertion was detected without an observed signature indicator.",
                name="Assertion",
                value=effective_assertion,
            )

        unique_types: list[SAMLIndicatorType] = []
        for indicator in indicators:
            if indicator.type not in unique_types:
                unique_types.append(indicator.type)

        unique_names: list[str] = []
        for indicator in indicators:
            if indicator.name and indicator.name not in unique_names:
                unique_names.append(indicator.name)

        return SAMLAnalysis(
            detected=bool(indicators),
            count=len(indicators),
            types=tuple(unique_types),
            names=tuple(unique_names),
            indicators=tuple(indicators),
        )
