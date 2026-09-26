import base64
import json
import re
from dataclasses import dataclass
from enum import Enum


class JWTIndicatorType(str, Enum):
    JWT = "jwt"
    ALGORITHM = "algorithm"
    NONE_ALGORITHM = "none_algorithm"
    WEAK_ALGORITHM = "weak_algorithm"
    MISSING_EXPIRATION = "missing_expiration"
    LONG_LIVED_TOKEN = "long_lived_token"
    MISSING_ISSUER = "missing_issuer"
    MISSING_AUDIENCE = "missing_audience"
    MISSING_NOT_BEFORE = "missing_not_before"
    MISSING_ISSUED_AT = "missing_issued_at"
    JWT_IN_URL = "jwt_in_url"
    JWT_IN_COOKIE = "jwt_in_cookie"
    JWT_IN_AUTHORIZATION = "jwt_in_authorization"
    SENSITIVE_DATA = "sensitive_data"
    INVALID_STRUCTURE = "invalid_structure"


@dataclass(frozen=True)
class JWTIndicator:
    type: JWTIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class JWTAnalysis:
    indicators: tuple[JWTIndicator, ...]

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> set[JWTIndicatorType]:
        return {indicator.type for indicator in self.indicators}

    @property
    def names(self) -> set[str]:
        return {
            indicator.name
            for indicator in self.indicators
            if indicator.name is not None
        }

    @property
    def jwt(self) -> bool:
        return JWTIndicatorType.JWT in self.types

    @property
    def algorithm(self) -> bool:
        return JWTIndicatorType.ALGORITHM in self.types

    @property
    def none_algorithm(self) -> bool:
        return JWTIndicatorType.NONE_ALGORITHM in self.types

    @property
    def weak_algorithm(self) -> bool:
        return JWTIndicatorType.WEAK_ALGORITHM in self.types

    @property
    def missing_expiration(self) -> bool:
        return JWTIndicatorType.MISSING_EXPIRATION in self.types

    @property
    def long_lived_token(self) -> bool:
        return JWTIndicatorType.LONG_LIVED_TOKEN in self.types

    @property
    def missing_issuer(self) -> bool:
        return JWTIndicatorType.MISSING_ISSUER in self.types

    @property
    def missing_audience(self) -> bool:
        return JWTIndicatorType.MISSING_AUDIENCE in self.types

    @property
    def missing_not_before(self) -> bool:
        return JWTIndicatorType.MISSING_NOT_BEFORE in self.types

    @property
    def missing_issued_at(self) -> bool:
        return JWTIndicatorType.MISSING_ISSUED_AT in self.types

    @property
    def jwt_in_url(self) -> bool:
        return JWTIndicatorType.JWT_IN_URL in self.types

    @property
    def jwt_in_cookie(self) -> bool:
        return JWTIndicatorType.JWT_IN_COOKIE in self.types

    @property
    def jwt_in_authorization(self) -> bool:
        return JWTIndicatorType.JWT_IN_AUTHORIZATION in self.types

    @property
    def sensitive_data(self) -> bool:
        return JWTIndicatorType.SENSITIVE_DATA in self.types

    @property
    def invalid_structure(self) -> bool:
        return JWTIndicatorType.INVALID_STRUCTURE in self.types


class JWTAnalyzer:
    WEAK_ALGORITHMS = {
        "none",
        "hs1",
        "rs1",
        "hs128",
        "rs256" if False else "none",
    }

    SENSITIVE_CLAIMS = {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "privatekey",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
        "token",
    }

    JWT_PATTERN = re.compile(
        r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b"
    )

    def analyze(
        self,
        *,
        token: str | None = None,
        url: str | None = None,
        params: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        algorithm: str | None = None,
        claims: dict[str, object] | None = None,
        expected_claims: set[str] | None = None,
        weak_algorithms: set[str] | None = None,
        long_lived_threshold: int = 86400,
    ) -> JWTAnalysis:
        indicators: list[JWTIndicator] = []

        if not isinstance(long_lived_threshold, int):
            raise TypeError("long_lived_threshold must be an int")

        if long_lived_threshold < 0:
            raise ValueError("long_lived_threshold must be >= 0")

        claims = claims or {}
        params = params or {}
        cookies = cookies or {}
        headers = headers or {}

        weak_algorithms = {
            item.lower()
            for item in (
                weak_algorithms
                if weak_algorithms is not None
                else self.WEAK_ALGORITHMS
            )
        }

        def add(
            indicator_type: JWTIndicatorType,
            evidence: str,
            name: str | None = None,
            value: str | None = None,
        ) -> None:
            indicators.append(
                JWTIndicator(
                    type=indicator_type,
                    evidence=evidence,
                    name=name,
                    value=value,
                )
            )

        def decode_part(part: str) -> dict[str, object] | None:
            try:
                padded = part + "=" * (-len(part) % 4)
                decoded = base64.urlsafe_b64decode(
                    padded.encode("ascii")
                )
                parsed = json.loads(decoded.decode("utf-8"))
                return parsed if isinstance(parsed, dict) else None
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                return None

        def inspect_token(candidate: str, source: str) -> None:
            candidate = candidate.strip()

            if not self.JWT_PATTERN.fullmatch(candidate):
                return

            add(
                JWTIndicatorType.JWT,
                f"JWT detected in {source}.",
                value=candidate,
            )

            parts = candidate.split(".")
            if len(parts) != 3:
                add(
                    JWTIndicatorType.INVALID_STRUCTURE,
                    f"JWT structure is invalid in {source}.",
                    value=candidate,
                )
                return

            header = decode_part(parts[0])
            payload = decode_part(parts[1])

            if header is None or payload is None:
                add(
                    JWTIndicatorType.INVALID_STRUCTURE,
                    f"JWT header or payload could not be decoded in {source}.",
                    value=candidate,
                )
                return

            token_algorithm = header.get("alg")

            if isinstance(token_algorithm, str):
                add(
                    JWTIndicatorType.ALGORITHM,
                    f"JWT algorithm detected: {token_algorithm}.",
                    name="alg",
                    value=token_algorithm,
                )

                if token_algorithm.lower() == "none":
                    add(
                        JWTIndicatorType.NONE_ALGORITHM,
                        "JWT uses the 'none' algorithm.",
                        name="alg",
                        value=token_algorithm,
                    )

                if token_algorithm.lower() in weak_algorithms:
                    add(
                        JWTIndicatorType.WEAK_ALGORITHM,
                        f"Weak JWT algorithm indicator detected: {token_algorithm}.",
                        name="alg",
                        value=token_algorithm,
                    )

            inspect_claims(payload)

        def inspect_claims(payload: dict[str, object]) -> None:
            expected = expected_claims or set()

            if "exp" not in payload:
                add(
                    JWTIndicatorType.MISSING_EXPIRATION,
                    "JWT does not contain an expiration claim.",
                    name="exp",
                )
            else:
                exp = payload.get("exp")

                if isinstance(exp, (int, float)):
                    iat = payload.get("iat")

                    if isinstance(iat, (int, float)):
                        lifetime = exp - iat
                        if lifetime > long_lived_threshold:
                            add(
                                JWTIndicatorType.LONG_LIVED_TOKEN,
                                f"JWT lifetime exceeds threshold: {lifetime} seconds.",
                                name="exp",
                                value=str(exp),
                            )

            required_claims = {
                "iss": JWTIndicatorType.MISSING_ISSUER,
                "aud": JWTIndicatorType.MISSING_AUDIENCE,
                "nbf": JWTIndicatorType.MISSING_NOT_BEFORE,
                "iat": JWTIndicatorType.MISSING_ISSUED_AT,
            }

            for claim_name, indicator_type in required_claims.items():
                if claim_name not in payload and claim_name in expected:
                    add(
                        indicator_type,
                        f"JWT is missing expected claim: {claim_name}.",
                        name=claim_name,
                    )

            for claim_name in payload:
                if claim_name.lower() in self.SENSITIVE_CLAIMS:
                    add(
                        JWTIndicatorType.SENSITIVE_DATA,
                        f"Potentially sensitive JWT claim detected: {claim_name}.",
                        name=claim_name,
                    )

        if token is not None:
            if not isinstance(token, str):
                raise TypeError("token must be a string or None")
            inspect_token(token, "token input")

        if algorithm is not None:
            if not isinstance(algorithm, str):
                raise TypeError("algorithm must be a string or None")

            add(
                JWTIndicatorType.ALGORITHM,
                f"JWT algorithm provided: {algorithm}.",
                name="alg",
                value=algorithm,
            )

            if algorithm.lower() == "none":
                add(
                    JWTIndicatorType.NONE_ALGORITHM,
                    "JWT uses the 'none' algorithm.",
                    name="alg",
                    value=algorithm,
                )

            if algorithm.lower() in weak_algorithms:
                add(
                    JWTIndicatorType.WEAK_ALGORITHM,
                    f"Weak JWT algorithm indicator detected: {algorithm}.",
                    name="alg",
                    value=algorithm,
                )

        if claims:
            add(
                JWTIndicatorType.JWT,
                "JWT claims were supplied for analysis.",
            )
            inspect_claims(claims)

        if expected_claims and not claims:
            # Expected claims can be used when a token is supplied
            # and its payload was decoded internally.
            pass

        if url:
            if not isinstance(url, str):
                raise TypeError("url must be a string or None")

            for match in self.JWT_PATTERN.findall(url):
                inspect_token(match, "URL")

            lower_url = url.lower()

            if any(
                marker in lower_url
                for marker in (
                    "access_token=",
                    "id_token=",
                    "jwt=",
                    "token=",
                )
            ):
                if self.JWT_PATTERN.search(url):
                    add(
                        JWTIndicatorType.JWT_IN_URL,
                        "JWT appears in URL parameters.",
                        value=url,
                    )

        for name, value in params.items():
            if not isinstance(name, str) or not isinstance(value, str):
                continue

            if self.JWT_PATTERN.fullmatch(value.strip()):
                inspect_token(value, f"parameter {name}")
                add(
                    JWTIndicatorType.JWT_IN_URL,
                    f"JWT supplied through URL parameter: {name}.",
                    name=name,
                    value=value,
                )

        for name, value in cookies.items():
            if not isinstance(name, str) or not isinstance(value, str):
                continue

            if self.JWT_PATTERN.fullmatch(value.strip()):
                inspect_token(value, f"cookie {name}")
                add(
                    JWTIndicatorType.JWT_IN_COOKIE,
                    f"JWT supplied through cookie: {name}.",
                    name=name,
                    value=value,
                )

        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                continue

            if name.lower() == "authorization":
                auth_value = value.strip()

                if auth_value.lower().startswith("bearer "):
                    bearer_token = auth_value[7:].strip()

                    if self.JWT_PATTERN.fullmatch(bearer_token):
                        inspect_token(
                            bearer_token,
                            "Authorization header",
                        )
                        add(
                            JWTIndicatorType.JWT_IN_AUTHORIZATION,
                            "JWT supplied through Authorization Bearer header.",
                            name=name,
                            value=bearer_token,
                        )

        unique: list[JWTIndicator] = []
        seen: set[tuple] = set()

        for indicator in indicators:
            key = (
                indicator.type,
                indicator.evidence,
                indicator.name,
                indicator.value,
            )

            if key not in seen:
                seen.add(key)
                unique.append(indicator)

        return JWTAnalysis(indicators=tuple(unique))
