from dataclasses import dataclass, field
from enum import Enum


class TLSIndicatorType(str, Enum):
    TLS_PRESENT = "tls_present"
    TLS_VERSION = "tls_version"
    SSLV2 = "sslv2"
    SSLV3 = "sslv3"
    TLS10 = "tls10"
    TLS11 = "tls11"
    TLS12 = "tls12"
    TLS13 = "tls13"
    EXPIRED_CERTIFICATE = "expired_certificate"
    SELF_SIGNED_CERTIFICATE = "self_signed_certificate"
    HOSTNAME_MISMATCH = "hostname_mismatch"
    INVALID_CERTIFICATE_CHAIN = "invalid_certificate_chain"
    WEAK_CIPHER = "weak_cipher"
    WEAK_KEY_EXCHANGE = "weak_key_exchange"
    WEAK_SIGNATURE = "weak_signature"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    CERTIFICATE_PRESENT = "certificate_present"
    HSTS_PRESENT = "hsts_present"


@dataclass(frozen=True)
class TLSIndicator:
    type: TLSIndicatorType
    name: str
    value: str | None = None


@dataclass(frozen=True)
class TLSAnalysis:
    detected: bool
    indicators: tuple[TLSIndicator, ...] = field(
        default_factory=tuple
    )

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> tuple[TLSIndicatorType, ...]:
        return tuple(
            indicator.type
            for indicator in self.indicators
        )

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(
            indicator.name
            for indicator in self.indicators
        )

    def has_type(
        self,
        indicator_type: TLSIndicatorType,
    ) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class TLSSecurityAnalyzer:
    name = "tls_security"
    description = (
        "Analyze TLS/SSL security configuration and certificate indicators"
    )

    def analyze(
        self,
        *,
        tls_version: str | None = None,
        certificate_present: bool = False,
        certificate_expired: bool = False,
        self_signed: bool = False,
        hostname_mismatch: bool = False,
        invalid_chain: bool = False,
        cipher: str | None = None,
        key_exchange: str | None = None,
        signature_algorithm: str | None = None,
        certificate_transparency: bool = False,
        hsts_present: bool = False,
    ) -> TLSAnalysis:
        indicators: list[TLSIndicator] = []

        if not isinstance(certificate_present, bool):
            raise TypeError(
                "certificate_present must be a boolean"
            )

        if not isinstance(certificate_expired, bool):
            raise TypeError(
                "certificate_expired must be a boolean"
            )

        if not isinstance(self_signed, bool):
            raise TypeError(
                "self_signed must be a boolean"
            )

        if not isinstance(hostname_mismatch, bool):
            raise TypeError(
                "hostname_mismatch must be a boolean"
            )

        if not isinstance(invalid_chain, bool):
            raise TypeError(
                "invalid_chain must be a boolean"
            )

        if not isinstance(certificate_transparency, bool):
            raise TypeError(
                "certificate_transparency must be a boolean"
            )

        if not isinstance(hsts_present, bool):
            raise TypeError(
                "hsts_present must be a boolean"
            )

        if tls_version is not None:
            if not isinstance(tls_version, str):
                raise TypeError(
                    "tls_version must be a string or None"
                )

            indicators.append(
                TLSIndicator(
                    type=TLSIndicatorType.TLS_PRESENT,
                    name="TLS is in use",
                    value=tls_version,
                )
            )

            indicators.append(
                TLSIndicator(
                    type=TLSIndicatorType.TLS_VERSION,
                    name="TLS protocol version",
                    value=tls_version,
                )
            )

            version_map = {
                "SSLv2": TLSIndicatorType.SSLV2,
                "SSLv3": TLSIndicatorType.SSLV3,
                "TLSv1": TLSIndicatorType.TLS10,
                "TLSv1.0": TLSIndicatorType.TLS10,
                "TLSv1.1": TLSIndicatorType.TLS11,
                "TLSv1.2": TLSIndicatorType.TLS12,
                "TLSv1.3": TLSIndicatorType.TLS13,
            }

            indicator_type = version_map.get(tls_version)

            if indicator_type is not None:
                indicators.append(
                    TLSIndicator(
                        type=indicator_type,
                        name=f"Protocol {tls_version}",
                        value=tls_version,
                    )
                )

        if certificate_present:
            indicators.append(
                TLSIndicator(
                    type=TLSIndicatorType.CERTIFICATE_PRESENT,
                    name="TLS certificate is present",
                )
            )

        if certificate_expired:
            indicators.append(
                TLSIndicator(
                    type=TLSIndicatorType.EXPIRED_CERTIFICATE,
                    name="TLS certificate is expired",
                )
            )

        if self_signed:
            indicators.append(
                TLSIndicator(
                    type=TLSIndicatorType.SELF_SIGNED_CERTIFICATE,
                    name="TLS certificate is self-signed",
                )
            )

        if hostname_mismatch:
            indicators.append(
                TLSIndicator(
                    type=TLSIndicatorType.HOSTNAME_MISMATCH,
                    name="TLS certificate hostname mismatch detected",
                )
            )

        if invalid_chain:
            indicators.append(
                TLSIndicator(
                    type=TLSIndicatorType.INVALID_CERTIFICATE_CHAIN,
                    name="TLS certificate chain is invalid",
                )
            )

        if cipher is not None:
            if not isinstance(cipher, str):
                raise TypeError(
                    "cipher must be a string or None"
                )

            lowered = cipher.lower()

            weak_cipher_markers = (
                "rc4",
                "3des",
                "des-",
                "null",
                "export",
                "anon",
                "md5",
            )

            if any(
                marker in lowered
                for marker in weak_cipher_markers
            ):
                indicators.append(
                    TLSIndicator(
                        type=TLSIndicatorType.WEAK_CIPHER,
                        name="Weak TLS cipher detected",
                        value=cipher,
                    )
                )

        if key_exchange is not None:
            if not isinstance(key_exchange, str):
                raise TypeError(
                    "key_exchange must be a string or None"
                )

            lowered = key_exchange.lower()

            weak_key_exchange_markers = (
                "anon",
                "export",
                "dh_",
                "static-dh",
            )

            if any(
                marker in lowered
                for marker in weak_key_exchange_markers
            ):
                indicators.append(
                    TLSIndicator(
                        type=TLSIndicatorType.WEAK_KEY_EXCHANGE,
                        name="Weak TLS key exchange detected",
                        value=key_exchange,
                    )
                )

        if signature_algorithm is not None:
            if not isinstance(signature_algorithm, str):
                raise TypeError(
                    "signature_algorithm must be a string or None"
                )

            lowered = signature_algorithm.lower()

            weak_signature_markers = (
                "md5",
                "sha1",
            )

            if any(
                marker in lowered
                for marker in weak_signature_markers
            ):
                indicators.append(
                    TLSIndicator(
                        type=TLSIndicatorType.WEAK_SIGNATURE,
                        name="Weak certificate signature algorithm detected",
                        value=signature_algorithm,
                    )
                )

        if certificate_transparency:
            indicators.append(
                TLSIndicator(
                    type=TLSIndicatorType.CERTIFICATE_TRANSPARENCY,
                    name="Certificate Transparency information is present",
                )
            )

        if hsts_present:
            indicators.append(
                TLSIndicator(
                    type=TLSIndicatorType.HSTS_PRESENT,
                    name="HTTP Strict Transport Security is present",
                )
            )

        return TLSAnalysis(
            detected=bool(indicators),
            indicators=tuple(indicators),
        )
