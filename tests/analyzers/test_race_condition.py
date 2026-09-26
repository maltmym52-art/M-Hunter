import pytest

from m_hunter.analyzers.race_condition import (
    RaceConditionAnalyzer,
    RaceConditionIndicatorType,
)


@pytest.fixture
def analyzer():
    return RaceConditionAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()
    assert not result.detected
    assert result.count == 0
    assert result.types == []


@pytest.mark.parametrize(
    "kwargs, indicator_type",
    [
        ({"concurrent_requests": 2}, RaceConditionIndicatorType.CONCURRENT_REQUEST),
        ({"repeated_requests": 2}, RaceConditionIndicatorType.REPEATED_REQUEST),
        ({"state_changed": True}, RaceConditionIndicatorType.STATE_CHANGE),
        ({"duplicate_operation": True}, RaceConditionIndicatorType.DUPLICATE_OPERATION),
        ({"method": "POST"}, RaceConditionIndicatorType.NON_IDEMPOTENT_OPERATION),
        ({"url": "/api/transfer"}, RaceConditionIndicatorType.SENSITIVE_OPERATION),
        ({"balance_changed": True}, RaceConditionIndicatorType.BALANCE_CHANGE),
        ({"coupon_redeemed": True}, RaceConditionIndicatorType.COUPON_REDEMPTION),
        ({"password_changed": True}, RaceConditionIndicatorType.PASSWORD_CHANGE),
        ({"mfa_operation": True}, RaceConditionIndicatorType.MFA_OPERATION),
        ({"token_rotated": True}, RaceConditionIndicatorType.TOKEN_ROTATION),
        ({"resource_created": True}, RaceConditionIndicatorType.RESOURCE_CREATION),
        ({"resource_deleted": True}, RaceConditionIndicatorType.RESOURCE_DELETION),
        ({"response_variation": True}, RaceConditionIndicatorType.RESPONSE_VARIATION),
    ],
)
def test_indicator_detection(analyzer, kwargs, indicator_type):
    result = analyzer.analyze(**kwargs)
    assert result.detected
    assert result.has_type(indicator_type)


def test_multiple_indicators(analyzer):
    result = analyzer.analyze(
        method="POST",
        url="/api/transfer",
        concurrent_requests=5,
        repeated_requests=3,
        state_changed=True,
        duplicate_operation=True,
        balance_changed=True,
        response_variation=True,
    )

    assert result.detected
    assert result.count >= 7
    assert result.has_type(RaceConditionIndicatorType.CONCURRENT_REQUEST)
    assert result.has_type(RaceConditionIndicatorType.DUPLICATE_OPERATION)
    assert result.has_type(RaceConditionIndicatorType.BALANCE_CHANGE)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"concurrent_requests": -1},
        {"repeated_requests": -1},
    ],
)
def test_negative_counts_rejected(analyzer, kwargs):
    with pytest.raises(ValueError):
        analyzer.analyze(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"method": 123},
        {"url": 123},
        {"params": "bad"},
        {"body": 123},
    ],
)
def test_invalid_types_rejected(analyzer, kwargs):
    with pytest.raises(TypeError):
        analyzer.analyze(**kwargs)


def test_bytes_body_supported(analyzer):
    result = analyzer.analyze(body=b"/api/payment")
    assert result.detected
    assert result.has_type(RaceConditionIndicatorType.SENSITIVE_OPERATION)


def test_names_and_values(analyzer):
    result = analyzer.analyze(
        url="/api/coupon/redeem",
        concurrent_requests=4,
    )

    assert "coupon" in result.names
    assert any(i.value == "coupon" for i in result.indicators)


def test_types_are_unique(analyzer):
    result = analyzer.analyze(
        url="/api/payment/payment",
        params={"payment": "true"},
    )

    assert result.types.count(RaceConditionIndicatorType.SENSITIVE_OPERATION) == 1
