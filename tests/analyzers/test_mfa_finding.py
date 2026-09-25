import pytest

from m_hunter.analyzers.mfa import (
    MFAAnalyzer,
    MFAIndicatorType,
)
from m_hunter.analyzers.mfa_finding import (
    MFAFindingAnalyzer,
)
from m_hunter.core.finding import Finding


@pytest.fixture
def analyzer():
    return MFAAnalyzer()


@pytest.fixture
def finding_analyzer():
    return MFAFindingAnalyzer()


def test_empty_analysis_returns_no_findings(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze()

    assert finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    ) == []


@pytest.mark.parametrize(
    "kwargs,indicator_type,severity,confidence,cwe",
    [
        (
            {"mfa": True},
            MFAIndicatorType.MFA,
            "Info",
            "High",
            "CWE-308",
        ),
        (
            {"otp": True},
            MFAIndicatorType.OTP,
            "Info",
            "High",
            "CWE-308",
        ),
        (
            {"totp": True},
            MFAIndicatorType.TOTP,
            "Info",
            "High",
            "CWE-308",
        ),
        (
            {"sms_mfa": True},
            MFAIndicatorType.SMS_MFA,
            "Low",
            "High",
            "CWE-308",
        ),
        (
            {"email_mfa": True},
            MFAIndicatorType.EMAIL_MFA,
            "Low",
            "High",
            "CWE-308",
        ),
        (
            {"recovery_code": True},
            MFAIndicatorType.RECOVERY_CODE,
            "Low",
            "High",
            "CWE-308",
        ),
        (
            {"backup_code": True},
            MFAIndicatorType.BACKUP_CODE,
            "Low",
            "High",
            "CWE-308",
        ),
        (
            {"remember_device": True},
            MFAIndicatorType.REMEMBER_DEVICE,
            "Medium",
            "Medium",
            "CWE-613",
        ),
        (
            {"trusted_device": True},
            MFAIndicatorType.TRUSTED_DEVICE,
            "Medium",
            "Medium",
            "CWE-613",
        ),
        (
            {"bypass_indicator": True},
            MFAIndicatorType.MFA_BYPASS_INDICATOR,
            "High",
            "Medium",
            "CWE-308",
        ),
        (
            {"enrollment": True},
            MFAIndicatorType.MFA_ENROLLMENT,
            "Low",
            "High",
            "CWE-308",
        ),
        (
            {"disable": True},
            MFAIndicatorType.MFA_DISABLE,
            "Medium",
            "Medium",
            "CWE-308",
        ),
        (
            {"verification": True},
            MFAIndicatorType.MFA_VERIFICATION,
            "Info",
            "High",
            "CWE-308",
        ),
    ],
)
def test_indicator_metadata(
    analyzer,
    finding_analyzer,
    kwargs,
    indicator_type,
    severity,
    confidence,
    cwe,
):
    analysis = analyzer.analyze(**kwargs)

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    matching = [
        finding
        for finding in findings
        if finding.cwe == cwe
        and finding.severity == severity
        and finding.confidence == confidence
    ]

    assert matching

    finding = matching[0]

    assert isinstance(finding, Finding)
    assert finding.cwe == cwe
    assert finding.owasp == "OWASP A07:2021"


def test_mfa_recovery_metadata(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"recovery": "true"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.cwe == "CWE-640"
        and finding.severity == "Medium"
        for finding in findings
    )


def test_challenge_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        body="mfa_challenge"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.title
        == "MFA challenge indicator detected."
        for finding in findings
    )


def test_bypass_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        body="skip_mfa=true"
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert any(
        finding.cwe == "CWE-308"
        and finding.severity == "High"
        for finding in findings
    )


def test_findings_include_target_and_endpoint(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        otp=True
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
        endpoint="/login",
    )

    assert findings
    assert findings[0].target == "https://example.com"
    assert findings[0].endpoint == "/login"


def test_description(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        mfa=True
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.description
    assert "does not prove a vulnerability" in finding.description


def test_evidence(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={"otp": "123456"}
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings
    assert findings[0].evidence
    assert "otp" in findings[0].evidence.lower()
    assert "123456" in findings[0].evidence


def test_remediation(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        disable=True
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.remediation
    assert "server-side" in finding.remediation


def test_multiple_indicators_create_multiple_findings(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        mfa=True,
        otp=True,
        totp=True,
        backup_code=True,
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert len(findings) >= 4


def test_duplicate_indicator_types_are_grouped(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={
            "mfa": "true",
            "2fa": "true",
        }
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    mfa_findings = [
        finding
        for finding in findings
        if finding.title
        == "Multi-factor authentication indicator detected."
    ]

    assert len(mfa_findings) == 1


def test_findings_have_open_status(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        mfa=True
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.status == "open"


def test_findings_have_ids(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        mfa=True
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.id


def test_all_indicator_types_have_metadata(
    finding_analyzer,
):
    for indicator_type in MFAIndicatorType:
        assert indicator_type in finding_analyzer.METADATA


def test_invalid_analysis_type(
    finding_analyzer,
):
    with pytest.raises(TypeError):
        finding_analyzer.analyze(
            object(),
            target="https://example.com",
        )


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        None,
        123,
    ],
)
def test_invalid_target(
    analyzer,
    finding_analyzer,
    target,
):
    analysis = analyzer.analyze(mfa=True)

    with pytest.raises((ValueError, TypeError)):
        finding_analyzer.analyze(
            analysis,
            target=target,
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        123,
        [],
        {},
    ],
)
def test_invalid_endpoint(
    analyzer,
    finding_analyzer,
    endpoint,
):
    analysis = analyzer.analyze(mfa=True)

    with pytest.raises(TypeError):
        finding_analyzer.analyze(
            analysis,
            target="https://example.com",
            endpoint=endpoint,
        )


def test_finding_determinism(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={
            "mfa": "true",
            "otp": "123456",
            "backup_code": "ABC",
        }
    )

    first = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    second = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert [
        (
            finding.title,
            finding.severity,
            finding.confidence,
            finding.cwe,
            finding.owasp,
            finding.evidence,
        )
        for finding in first
    ] == [
        (
            finding.title,
            finding.severity,
            finding.confidence,
            finding.cwe,
            finding.owasp,
            finding.evidence,
        )
        for finding in second
    ]


def test_header_indicator_creates_finding(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        headers={
            "X-MFA-Verification": "required",
        }
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings
    assert any(
        finding.cwe == "CWE-308"
        for finding in findings
    )


def test_finding_values_are_grouped(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        params={
            "otp": "111111",
        }
    )

    findings = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )

    assert findings
    assert "Values:" in findings[0].evidence


def test_remember_device_has_session_lifetime_metadata(
    analyzer,
    finding_analyzer,
):
    analysis = analyzer.analyze(
        remember_device=True
    )

    finding = finding_analyzer.analyze(
        analysis,
        target="https://example.com",
    )[0]

    assert finding.severity == "Medium"
    assert finding.confidence == "Medium"
    assert finding.cwe == "CWE-613"
