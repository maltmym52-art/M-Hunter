import pytest

from m_hunter.config.settings import (
    HttpSettings,
    ScanSettings,
    Settings,
)


def test_http_settings_defaults():
    settings = HttpSettings()

    assert settings.timeout == 10.0
    assert settings.follow_redirects is True
    assert settings.user_agent == "M-Hunter/0.1.0"


def test_http_settings_custom_values():
    settings = HttpSettings(
        timeout=30.0,
        follow_redirects=False,
        user_agent="Custom-Agent/1.0",
    )

    assert settings.timeout == 30.0
    assert settings.follow_redirects is False
    assert settings.user_agent == "Custom-Agent/1.0"


def test_http_settings_rejects_zero_timeout():
    with pytest.raises(
        ValueError,
        match="timeout must be greater than 0",
    ):
        HttpSettings(timeout=0)


def test_http_settings_rejects_negative_timeout():
    with pytest.raises(
        ValueError,
        match="timeout must be greater than 0",
    ):
        HttpSettings(timeout=-1)


def test_http_settings_rejects_empty_user_agent():
    with pytest.raises(
        ValueError,
        match="user_agent must not be empty",
    ):
        HttpSettings(user_agent="")


def test_http_settings_rejects_whitespace_user_agent():
    with pytest.raises(
        ValueError,
        match="user_agent must not be empty",
    ):
        HttpSettings(user_agent="   ")


def test_scan_settings_defaults():
    settings = ScanSettings()

    assert settings.auto_discover_scanners is True


def test_scan_settings_can_disable_auto_discovery():
    settings = ScanSettings(
        auto_discover_scanners=False,
    )

    assert settings.auto_discover_scanners is False


def test_settings_defaults():
    settings = Settings()

    assert isinstance(settings.http, HttpSettings)
    assert isinstance(settings.scan, ScanSettings)

    assert settings.http.timeout == 10.0
    assert settings.http.follow_redirects is True
    assert settings.http.user_agent == "M-Hunter/0.1.0"

    assert settings.scan.auto_discover_scanners is True


def test_settings_accepts_custom_http_settings():
    http_settings = HttpSettings(
        timeout=20.0,
        follow_redirects=False,
        user_agent="Test-Agent/1.0",
    )

    settings = Settings(
        http=http_settings,
    )

    assert settings.http is http_settings
    assert settings.http.timeout == 20.0
    assert settings.http.follow_redirects is False
    assert settings.http.user_agent == "Test-Agent/1.0"


def test_settings_accepts_custom_scan_settings():
    scan_settings = ScanSettings(
        auto_discover_scanners=False,
    )

    settings = Settings(
        scan=scan_settings,
    )

    assert settings.scan is scan_settings
    assert settings.scan.auto_discover_scanners is False


def test_settings_instances_are_independent():
    first = Settings()
    second = Settings()

    first.http.timeout = 30.0
    first.scan.auto_discover_scanners = False

    assert second.http.timeout == 10.0
    assert second.scan.auto_discover_scanners is True
