import pytest

from m_hunter.analyzers.tls_security import (
    TLSAnalysis,
    TLSIndicator,
    TLSIndicatorType,
    TLSSecurityAnalyzer,
)


def test_name():
    assert TLSSecurityAnalyzer.name == "tls_security"


def test_description():
    assert "TLS" in TLSSecurityAnalyzer.description


def test_analysis_type():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )

    assert isinstance(result, TLSAnalysis)


def test_tls_present():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )

    assert result.has_type(TLSIndicatorType.TLS_PRESENT)


def test_tls_version():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )

    assert result.has_type(TLSIndicatorType.TLS_VERSION)


def test_tls13():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )

    assert result.has_type(TLSIndicatorType.TLS13)


def test_tls12():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.2"
    )

    assert result.has_type(TLSIndicatorType.TLS12)


def test_tls11():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.1"
    )

    assert result.has_type(TLSIndicatorType.TLS11)


def test_tls10():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.0"
    )

    assert result.has_type(TLSIndicatorType.TLS10)


def test_sslv3():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="SSLv3"
    )

    assert result.has_type(TLSIndicatorType.SSLV3)


def test_sslv2():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="SSLv2"
    )

    assert result.has_type(TLSIndicatorType.SSLV2)


def test_certificate():
    result = TLSSecurityAnalyzer().analyze(
        certificate_present=True
    )

    assert result.has_type(TLSIndicatorType.CERTIFICATE_PRESENT)


def test_expired_certificate():
    result = TLSSecurityAnalyzer().analyze(
        certificate_expired=True
    )

    assert result.has_type(
        TLSIndicatorType.EXPIRED_CERTIFICATE
    )


def test_self_signed_certificate():
    result = TLSSecurityAnalyzer().analyze(
        self_signed=True
    )

    assert result.has_type(
        TLSIndicatorType.SELF_SIGNED_CERTIFICATE
    )


def test_hostname_mismatch():
    result = TLSSecurityAnalyzer().analyze(
        hostname_mismatch=True
    )

    assert result.has_type(
        TLSIndicatorType.HOSTNAME_MISMATCH
    )


def test_invalid_chain():
    result = TLSSecurityAnalyzer().analyze(
        invalid_chain=True
    )

    assert result.has_type(
        TLSIndicatorType.INVALID_CERTIFICATE_CHAIN
    )


def test_weak_cipher():
    result = TLSSecurityAnalyzer().analyze(
        cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    )

    assert result.has_type(
        TLSIndicatorType.WEAK_CIPHER
    )


def test_weak_key_exchange():
    result = TLSSecurityAnalyzer().analyze(
        key_exchange="DH_anon"
    )

    assert result.has_type(
        TLSIndicatorType.WEAK_KEY_EXCHANGE
    )


def test_weak_signature():
    result = TLSSecurityAnalyzer().analyze(
        signature_algorithm="sha1WithRSAEncryption"
    )

    assert result.has_type(
        TLSIndicatorType.WEAK_SIGNATURE
    )


def test_certificate_transparency():
    result = TLSSecurityAnalyzer().analyze(
        certificate_transparency=True
    )

    assert result.has_type(
        TLSIndicatorType.CERTIFICATE_TRANSPARENCY
    )


def test_hsts():
    result = TLSSecurityAnalyzer().analyze(
        hsts_present=True
    )

    assert result.has_type(
        TLSIndicatorType.HSTS_PRESENT
    )


def test_all_security_indicators():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.2",
        certificate_present=True,
        certificate_expired=True,
        self_signed=True,
        hostname_mismatch=True,
        invalid_chain=True,
        cipher="RC4",
        key_exchange="DH_anon",
        signature_algorithm="SHA1",
        certificate_transparency=True,
        hsts_present=True,
    )

    assert result.detected
    assert result.count >= 10


def test_indicator_properties():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )

    assert result.count > 0
    assert result.types
    assert result.names


def test_indicator_value():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )

    indicator = next(
        item
        for item in result.indicators
        if item.type == TLSIndicatorType.TLS_VERSION
    )

    assert indicator.value == "TLSv1.3"


def test_frozen_indicator():
    indicator = TLSIndicator(
        type=TLSIndicatorType.TLS13,
        name="TLS 1.3",
        value="TLSv1.3",
    )

    with pytest.raises(Exception):
        indicator.value = "TLSv1.2"


def test_frozen_analysis():
    result = TLSSecurityAnalyzer().analyze(
        tls_version="TLSv1.3"
    )

    with pytest.raises(Exception):
        result.detected = False


def test_invalid_certificate_present():
    with pytest.raises(TypeError):
        TLSSecurityAnalyzer().analyze(
            certificate_present=1
        )


def test_invalid_tls_version():
    with pytest.raises(TypeError):
        TLSSecurityAnalyzer().analyze(
            tls_version=1.3
        )


def test_invalid_cipher():
    with pytest.raises(TypeError):
        TLSSecurityAnalyzer().analyze(
            cipher=123
        )


def test_invalid_key_exchange():
    with pytest.raises(TypeError):
        TLSSecurityAnalyzer().analyze(
            key_exchange=123
        )


def test_invalid_signature_algorithm():
    with pytest.raises(TypeError):
        TLSSecurityAnalyzer().analyze(
            signature_algorithm=123
        )
