import pytest

from m_hunter.analyzers.mfa import (
    MFAAnalysis,
    MFAAnalyzer,
    MFAIndicatorType,
)


@pytest.fixture
def analyzer():
    return MFAAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()

    assert isinstance(result, MFAAnalysis)
    assert result.detected is False
    assert result.count == 0
    assert result.types == ()
    assert result.names == ()
    assert result.indicators == ()


@pytest.mark.parametrize(
    "kwargs, indicator_type",
    [
        ({"mfa": True}, MFAIndicatorType.MFA),
        ({"otp": True}, MFAIndicatorType.OTP),
        ({"totp": True}, MFAIndicatorType.TOTP),
        ({"sms_mfa": True}, MFAIndicatorType.SMS_MFA),
        ({"email_mfa": True}, MFAIndicatorType.EMAIL_MFA),
        ({"recovery_code": True}, MFAIndicatorType.RECOVERY_CODE),
        ({"backup_code": True}, MFAIndicatorType.BACKUP_CODE),
        ({"remember_device": True}, MFAIndicatorType.REMEMBER_DEVICE),
        ({"trusted_device": True}, MFAIndicatorType.TRUSTED_DEVICE),
        (
            {"bypass_indicator": True},
            MFAIndicatorType.MFA_BYPASS_INDICATOR,
        ),
        (
            {"enrollment": True},
            MFAIndicatorType.MFA_ENROLLMENT,
        ),
        (
            {"disable": True},
            MFAIndicatorType.MFA_DISABLE,
        ),
        (
            {"verification": True},
            MFAIndicatorType.MFA_VERIFICATION,
        ),
    ],
)
def test_explicit_indicators(
    analyzer,
    kwargs,
    indicator_type,
):
    result = analyzer.analyze(**kwargs)

    assert result.detected
    assert result.count >= 1
    assert indicator_type in result.types


@pytest.mark.parametrize(
    "params, indicator_type",
    [
        ({"mfa": "1"}, MFAIndicatorType.MFA),
        ({"2fa": "true"}, MFAIndicatorType.MFA),
        ({"two_factor": "1"}, MFAIndicatorType.MFA),
        ({"otp": "123456"}, MFAIndicatorType.OTP),
        ({"totp": "123456"}, MFAIndicatorType.TOTP),
        ({"authenticator": "1"}, MFAIndicatorType.TOTP),
        ({"sms_code": "123456"}, MFAIndicatorType.SMS_MFA),
        ({"phone_verification": "1"}, MFAIndicatorType.SMS_MFA),
        (
            {"email_verification": "1"},
            MFAIndicatorType.EMAIL_MFA,
        ),
        (
            {"recovery_code": "ABC"},
            MFAIndicatorType.MFA_RECOVERY,
        ),
        (
            {"backup_code": "ABC"},
            MFAIndicatorType.BACKUP_CODE,
        ),
        (
            {"remember_device": "true"},
            MFAIndicatorType.REMEMBER_DEVICE,
        ),
        (
            {"trusted_device": "true"},
            MFAIndicatorType.TRUSTED_DEVICE,
        ),
        (
            {"mfa_enrollment": "1"},
            MFAIndicatorType.MFA_ENROLLMENT,
        ),
        (
            {"disable_mfa": "1"},
            MFAIndicatorType.MFA_DISABLE,
        ),
        (
            {"mfa_verification": "1"},
            MFAIndicatorType.MFA_VERIFICATION,
        ),
    ],
)
def test_parameter_detection(
    analyzer,
    params,
    indicator_type,
):
    result = analyzer.analyze(params=params)

    assert result.detected
    assert indicator_type in result.types


def test_url_parameters_are_detected(analyzer):
    result = analyzer.analyze(
        url="https://example.com/login?otp=123456&mfa=true"
    )

    assert result.detected
    assert MFAIndicatorType.OTP in result.types
    assert MFAIndicatorType.MFA in result.types


def test_challenge_marker(analyzer):
    result = analyzer.analyze(
        body="POST /mfa_challenge"
    )

    assert result.challenge
    assert MFAIndicatorType.MFA_CHALLENGE in result.types


def test_bypass_marker(analyzer):
    result = analyzer.analyze(
        body="skip_mfa=true"
    )

    assert result.bypass_indicator
    assert MFAIndicatorType.MFA_BYPASS_INDICATOR in result.types


def test_multiple_indicators(analyzer):
    result = analyzer.analyze(
        params={
            "mfa": "true",
            "otp": "123456",
            "totp": "123456",
            "sms_code": "123456",
            "backup_code": "ABC",
        }
    )

    assert result.detected
    assert result.count >= 5
    assert MFAIndicatorType.MFA in result.types
    assert MFAIndicatorType.OTP in result.types
    assert MFAIndicatorType.TOTP in result.types
    assert MFAIndicatorType.SMS_MFA in result.types
    assert MFAIndicatorType.BACKUP_CODE in result.types


def test_names_are_unique(analyzer):
    result = analyzer.analyze(
        params={
            "mfa": "1",
        },
        url="https://example.com/login?mfa=2",
    )

    assert result.names.count("mfa") == 1


def test_types_are_unique(analyzer):
    result = analyzer.analyze(
        params={
            "mfa": "1",
            "2fa": "1",
        }
    )

    assert result.types.count(MFAIndicatorType.MFA) == 1


@pytest.mark.parametrize(
    "value",
    [
        None,
        "true",
        1,
        [],
        {},
    ],
)
def test_invalid_mfa_boolean(analyzer, value):
    if value is None:
        result = analyzer.analyze(mfa=None)
        assert not result.detected
        return

    with pytest.raises(TypeError):
        analyzer.analyze(mfa=value)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "true",
        1,
        [],
        {},
    ],
)
def test_invalid_otp_boolean(analyzer, value):
    if value is None:
        result = analyzer.analyze(otp=None)
        assert not result.detected
        return

    with pytest.raises(TypeError):
        analyzer.analyze(otp=value)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "true",
        1,
        [],
        {},
    ],
)
def test_invalid_totp_boolean(analyzer, value):
    if value is None:
        result = analyzer.analyze(totp=None)
        assert not result.detected
        return

    with pytest.raises(TypeError):
        analyzer.analyze(totp=value)


@pytest.mark.parametrize(
    "value",
    [
        1,
        [],
        {},
    ],
)
def test_invalid_url(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(url=value)


@pytest.mark.parametrize(
    "value",
    [
        [],
        "invalid",
        1,
    ],
)
def test_invalid_params(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(params=value)


@pytest.mark.parametrize(
    "value",
    [
        1,
        [],
        {},
    ],
)
def test_invalid_body(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(body=value)


@pytest.mark.parametrize(
    "value",
    [
        [],
        "invalid",
        1,
    ],
)
def test_invalid_headers(analyzer, value):
    with pytest.raises(TypeError):
        analyzer.analyze(headers=value)


def test_bytes_body_is_supported(analyzer):
    result = analyzer.analyze(
        body=b"POST /otp_challenge"
    )

    assert result.detected
    assert MFAIndicatorType.MFA_CHALLENGE in result.types


def test_header_detection(analyzer):
    result = analyzer.analyze(
        headers={
            "X-MFA-Verification": "required",
        }
    )

    assert result.detected
    assert result.verification


def test_explicit_false_does_not_create_indicator(analyzer):
    result = analyzer.analyze(
        mfa=False,
        otp=False,
        totp=False,
        sms_mfa=False,
        email_mfa=False,
    )

    assert result.detected is False


def test_convenience_properties(analyzer):
    result = analyzer.analyze(
        mfa=True,
        otp=True,
        totp=True,
        sms_mfa=True,
        email_mfa=True,
        recovery_code=True,
        backup_code=True,
        remember_device=True,
        trusted_device=True,
        bypass_indicator=True,
        enrollment=True,
        disable=True,
        verification=True,
    )

    assert result.mfa
    assert result.otp
    assert result.totp
    assert result.sms_mfa
    assert result.email_mfa
    assert result.recovery_code
    assert result.backup_code
    assert result.remember_device
    assert result.trusted_device
    assert result.bypass_indicator
    assert result.enrollment
    assert result.disable
    assert result.verification


def test_mfa_recovery_property(analyzer):
    result = analyzer.analyze(
        params={"recovery": "true"}
    )

    assert result.recovery
    assert MFAIndicatorType.MFA_RECOVERY in result.types


def test_indicator_fields(analyzer):
    result = analyzer.analyze(
        params={"otp": "123456"}
    )

    indicator = result.indicators[0]

    assert indicator.type == MFAIndicatorType.OTP
    assert indicator.name == "otp"
    assert indicator.value == "123456"
    assert indicator.evidence


def test_deterministic_output(analyzer):
    kwargs = {
        "params": {
            "mfa": "true",
            "otp": "123456",
            "backup_code": "ABC",
        }
    }

    first = analyzer.analyze(**kwargs)
    second = analyzer.analyze(**kwargs)

    assert first == second
