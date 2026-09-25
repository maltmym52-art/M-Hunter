from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qsl, urlparse


class MFAIndicatorType(str, Enum):
    MFA = "mfa"
    MFA_CHALLENGE = "mfa_challenge"
    OTP = "otp"
    TOTP = "totp"
    SMS_MFA = "sms_mfa"
    EMAIL_MFA = "email_mfa"
    RECOVERY_CODE = "recovery_code"
    BACKUP_CODE = "backup_code"
    REMEMBER_DEVICE = "remember_device"
    TRUSTED_DEVICE = "trusted_device"
    MFA_BYPASS_INDICATOR = "mfa_bypass_indicator"
    MFA_RECOVERY = "mfa_recovery"
    MFA_ENROLLMENT = "mfa_enrollment"
    MFA_DISABLE = "mfa_disable"
    MFA_VERIFICATION = "mfa_verification"


@dataclass(frozen=True)
class MFAIndicator:
    type: MFAIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class MFAAnalysis:
    detected: bool
    count: int
    types: tuple[MFAIndicatorType, ...]
    names: tuple[str, ...]
    indicators: tuple[MFAIndicator, ...]

    @property
    def mfa(self) -> bool:
        return MFAIndicatorType.MFA in self.types

    @property
    def challenge(self) -> bool:
        return MFAIndicatorType.MFA_CHALLENGE in self.types

    @property
    def otp(self) -> bool:
        return MFAIndicatorType.OTP in self.types

    @property
    def totp(self) -> bool:
        return MFAIndicatorType.TOTP in self.types

    @property
    def sms_mfa(self) -> bool:
        return MFAIndicatorType.SMS_MFA in self.types

    @property
    def email_mfa(self) -> bool:
        return MFAIndicatorType.EMAIL_MFA in self.types

    @property
    def recovery_code(self) -> bool:
        return MFAIndicatorType.RECOVERY_CODE in self.types

    @property
    def backup_code(self) -> bool:
        return MFAIndicatorType.BACKUP_CODE in self.types

    @property
    def remember_device(self) -> bool:
        return MFAIndicatorType.REMEMBER_DEVICE in self.types

    @property
    def trusted_device(self) -> bool:
        return MFAIndicatorType.TRUSTED_DEVICE in self.types

    @property
    def bypass_indicator(self) -> bool:
        return MFAIndicatorType.MFA_BYPASS_INDICATOR in self.types

    @property
    def recovery(self) -> bool:
        return MFAIndicatorType.MFA_RECOVERY in self.types

    @property
    def enrollment(self) -> bool:
        return MFAIndicatorType.MFA_ENROLLMENT in self.types

    @property
    def disable(self) -> bool:
        return MFAIndicatorType.MFA_DISABLE in self.types

    @property
    def verification(self) -> bool:
        return MFAIndicatorType.MFA_VERIFICATION in self.types


class MFAAnalyzer:
    """Detect MFA-related indicators without claiming exploitation."""

    MFA_KEYS = {
        "mfa",
        "2fa",
        "two_factor",
        "two-factor",
        "multifactor",
        "multi_factor",
        "multi-factor",
    }

    OTP_KEYS = {
        "otp",
        "one_time_password",
        "one-time-password",
        "verification_code",
        "verification-code",
    }

    TOTP_KEYS = {
        "totp",
        "authenticator",
        "authenticator_app",
    }

    SMS_KEYS = {
        "sms",
        "sms_code",
        "sms-code",
        "phone_verification",
    }

    EMAIL_KEYS = {
        "email_verification",
        "email-verification",
        "email_code",
    }

    RECOVERY_KEYS = {
        "recovery",
        "recovery_code",
        "recovery-code",
        "account_recovery",
    }

    BACKUP_KEYS = {
        "backup_code",
        "backup-code",
        "backup_codes",
    }

    REMEMBER_DEVICE_KEYS = {
        "remember_device",
        "remember-device",
        "remember_me",
    }

    TRUSTED_DEVICE_KEYS = {
        "trusted_device",
        "trusted-device",
        "device_trust",
    }

    ENROLLMENT_KEYS = {
        "mfa_enroll",
        "mfa-enroll",
        "mfa_enrollment",
        "mfa-enrollment",
        "enable_mfa",
        "enable-mfa",
    }

    DISABLE_KEYS = {
        "disable_mfa",
        "disable-mfa",
        "mfa_disable",
        "mfa-disable",
    }

    VERIFICATION_KEYS = {
        "mfa_verify",
        "mfa-verification",
        "mfa_verification",
        "verify_mfa",
        "verify-mfa",
    }

    BYPASS_MARKERS = {
        "mfa_bypass",
        "mfa-bypass",
        "skip_mfa",
        "skip-mfa",
        "bypass_mfa",
        "bypass-mfa",
        "mfa_optional",
        "mfa-optional",
    }

    CHALLENGE_MARKERS = {
        "mfa_challenge",
        "mfa-challenge",
        "2fa_challenge",
        "2fa-challenge",
        "otp_challenge",
        "otp-challenge",
    }

    def analyze(
        self,
        *,
        url: str | None = None,
        params: dict[str, str] | None = None,
        body: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        mfa: bool | None = None,
        otp: bool | None = None,
        totp: bool | None = None,
        sms_mfa: bool | None = None,
        email_mfa: bool | None = None,
        recovery_code: bool | None = None,
        backup_code: bool | None = None,
        remember_device: bool | None = None,
        trusted_device: bool | None = None,
        bypass_indicator: bool | None = None,
        enrollment: bool | None = None,
        disable: bool | None = None,
        verification: bool | None = None,
    ) -> MFAAnalysis:
        if url is not None and not isinstance(url, str):
            raise TypeError("url must be a string or None")

        if params is not None and not isinstance(params, dict):
            raise TypeError("params must be a dict or None")

        if body is not None and not isinstance(body, (str, bytes)):
            raise TypeError("body must be str, bytes, or None")

        if headers is not None and not isinstance(headers, dict):
            raise TypeError("headers must be a dict or None")

        boolean_values = {
            "mfa": mfa,
            "otp": otp,
            "totp": totp,
            "sms_mfa": sms_mfa,
            "email_mfa": email_mfa,
            "recovery_code": recovery_code,
            "backup_code": backup_code,
            "remember_device": remember_device,
            "trusted_device": trusted_device,
            "bypass_indicator": bypass_indicator,
            "enrollment": enrollment,
            "disable": disable,
            "verification": verification,
        }

        for name, value in boolean_values.items():
            if value is not None and not isinstance(value, bool):
                raise TypeError(f"{name} must be bool or None")

        normalized_params: dict[str, str] = {}

        if params:
            for name, value in params.items():
                normalized_params[str(name).lower()] = str(value)

        if url:
            parsed = urlparse(url)
            for name, value in parse_qsl(
                parsed.query,
                keep_blank_values=True,
            ):
                normalized_params.setdefault(
                    name.lower(),
                    value,
                )

        combined = " ".join(
            [
                url or "",
                " ".join(
                    f"{key}={value}"
                    for key, value in normalized_params.items()
                ),
                body.decode("utf-8", errors="replace")
                if isinstance(body, bytes)
                else body or "",
                " ".join(
                    f"{key}: {value}"
                    for key, value in (headers or {}).items()
                ),
            ]
        ).lower()

        indicators: list[MFAIndicator] = []

        def add(
            indicator_type: MFAIndicatorType,
            evidence: str,
            name: str | None = None,
            value: str | None = None,
        ) -> None:
            indicators.append(
                MFAIndicator(
                    type=indicator_type,
                    evidence=evidence,
                    name=name,
                    value=value,
                )
            )

        if mfa is True:
            add(
                MFAIndicatorType.MFA,
                "MFA explicitly indicated.",
            )

        if otp is True:
            add(
                MFAIndicatorType.OTP,
                "OTP explicitly indicated.",
            )

        if totp is True:
            add(
                MFAIndicatorType.TOTP,
                "TOTP explicitly indicated.",
            )

        if sms_mfa is True:
            add(
                MFAIndicatorType.SMS_MFA,
                "SMS-based MFA explicitly indicated.",
            )

        if email_mfa is True:
            add(
                MFAIndicatorType.EMAIL_MFA,
                "Email-based verification explicitly indicated.",
            )

        if recovery_code is True:
            add(
                MFAIndicatorType.RECOVERY_CODE,
                "MFA recovery code explicitly indicated.",
            )

        if backup_code is True:
            add(
                MFAIndicatorType.BACKUP_CODE,
                "MFA backup code explicitly indicated.",
            )

        if remember_device is True:
            add(
                MFAIndicatorType.REMEMBER_DEVICE,
                "Remember-device behavior explicitly indicated.",
            )

        if trusted_device is True:
            add(
                MFAIndicatorType.TRUSTED_DEVICE,
                "Trusted-device behavior explicitly indicated.",
            )

        if bypass_indicator is True:
            add(
                MFAIndicatorType.MFA_BYPASS_INDICATOR,
                "MFA bypass indicator explicitly indicated.",
            )

        if enrollment is True:
            add(
                MFAIndicatorType.MFA_ENROLLMENT,
                "MFA enrollment explicitly indicated.",
            )

        if disable is True:
            add(
                MFAIndicatorType.MFA_DISABLE,
                "MFA disable operation explicitly indicated.",
            )

        if verification is True:
            add(
                MFAIndicatorType.MFA_VERIFICATION,
                "MFA verification explicitly indicated.",
            )

        normalized_key_sets = (
            (self.MFA_KEYS, MFAIndicatorType.MFA, "MFA"),
            (self.OTP_KEYS, MFAIndicatorType.OTP, "OTP"),
            (self.TOTP_KEYS, MFAIndicatorType.TOTP, "TOTP"),
            (self.SMS_KEYS, MFAIndicatorType.SMS_MFA, "SMS MFA"),
            (self.EMAIL_KEYS, MFAIndicatorType.EMAIL_MFA, "Email MFA"),
            (
                self.RECOVERY_KEYS,
                MFAIndicatorType.MFA_RECOVERY,
                "MFA recovery",
            ),
            (
                self.BACKUP_KEYS,
                MFAIndicatorType.BACKUP_CODE,
                "MFA backup code",
            ),
            (
                self.REMEMBER_DEVICE_KEYS,
                MFAIndicatorType.REMEMBER_DEVICE,
                "Remember device",
            ),
            (
                self.TRUSTED_DEVICE_KEYS,
                MFAIndicatorType.TRUSTED_DEVICE,
                "Trusted device",
            ),
            (
                self.ENROLLMENT_KEYS,
                MFAIndicatorType.MFA_ENROLLMENT,
                "MFA enrollment",
            ),
            (
                self.DISABLE_KEYS,
                MFAIndicatorType.MFA_DISABLE,
                "MFA disable",
            ),
            (
                self.VERIFICATION_KEYS,
                MFAIndicatorType.MFA_VERIFICATION,
                "MFA verification",
            ),
        )

        for keys, indicator_type, label in normalized_key_sets:
            for key in keys:
                if key in normalized_params:
                    add(
                        indicator_type,
                        f"{label} parameter detected: {key}",
                        name=key,
                        value=normalized_params[key],
                    )

        for marker in self.CHALLENGE_MARKERS:
            if marker in combined:
                add(
                    MFAIndicatorType.MFA_CHALLENGE,
                    f"MFA challenge marker detected: {marker}",
                )

        for marker in self.BYPASS_MARKERS:
            if marker in combined:
                add(
                    MFAIndicatorType.MFA_BYPASS_INDICATOR,
                    f"MFA bypass marker detected: {marker}",
                )

        header_names = {
            str(name).lower().replace("_", "-")
            for name in (headers or {})
        }

        header_indicators = (
            (
                {"x-mfa", "x-mfa-verification", "mfa-verification"},
                MFAIndicatorType.MFA_VERIFICATION,
                "MFA verification header",
            ),
            (
                {"x-otp", "x-otp-verification", "otp-verification"},
                MFAIndicatorType.OTP,
                "OTP verification header",
            ),
            (
                {"x-2fa", "x-2fa-verification", "2fa-verification"},
                MFAIndicatorType.MFA,
                "2FA header",
            ),
            (
                {"x-mfa-challenge", "mfa-challenge"},
                MFAIndicatorType.MFA_CHALLENGE,
                "MFA challenge header",
            ),
        )

        for names_set, indicator_type, label in header_indicators:
            for header_name in names_set:
                if header_name in header_names:
                    add(
                        indicator_type,
                        f"{label} detected: {header_name}",
                        name=header_name,
                        value=str(
                            next(
                                (
                                    value
                                    for name, value in (headers or {}).items()
                                    if str(name).lower().replace("_", "-")
                                    == header_name
                                ),
                                "",
                            )
                        ),
                    )

        types: list[MFAIndicatorType] = []
        names: list[str] = []

        for indicator in indicators:
            if indicator.type not in types:
                types.append(indicator.type)

            if indicator.name and indicator.name not in names:
                names.append(indicator.name)

        return MFAAnalysis(
            detected=bool(indicators),
            count=len(indicators),
            types=tuple(types),
            names=tuple(names),
            indicators=tuple(indicators),
        )
