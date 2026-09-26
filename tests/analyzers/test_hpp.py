import pytest

from m_hunter.analyzers.hpp import (
    HPPAnalyzer,
    HPPIndicatorType,
)


@pytest.fixture
def analyzer():
    return HPPAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()

    assert not result.detected
    assert result.count == 0
    assert result.types == []
    assert result.names == []


def test_duplicate_query_parameter(analyzer):
    result = analyzer.analyze(
        url="https://example.com/search?id=1&id=2"
    )

    assert result.detected
    assert result.has_type(
        HPPIndicatorType.DUPLICATE_QUERY_PARAMETER
    )
    assert "id" in result.names


def test_conflicting_query_values(analyzer):
    result = analyzer.analyze(
        url="https://example.com/search?id=1&id=2"
    )

    assert result.has_type(
        HPPIndicatorType.CONFLICTING_VALUES
    )


def test_duplicate_query_same_value(analyzer):
    result = analyzer.analyze(
        url="https://example.com/search?id=1&id=1"
    )

    assert result.has_type(
        HPPIndicatorType.DUPLICATE_QUERY_PARAMETER
    )
    assert not any(
        indicator.type == HPPIndicatorType.CONFLICTING_VALUES
        for indicator in result.indicators
    )


def test_duplicate_parameter_list(analyzer):
    result = analyzer.analyze(
        params={"id": ["1", "2"]}
    )

    assert result.has_type(
        HPPIndicatorType.DUPLICATE_PARAMETER
    )
    assert result.has_type(
        HPPIndicatorType.PARAMETER_ARRAY
    )
    assert result.has_type(
        HPPIndicatorType.SAME_PARAMETER_DIFFERENT_VALUES
    )


def test_parameter_single_value(analyzer):
    result = analyzer.analyze(
        params={"id": "1"}
    )

    assert not result.detected


def test_duplicate_body_parameter(analyzer):
    result = analyzer.analyze(
        body="id=1&id=2"
    )

    assert result.has_type(
        HPPIndicatorType.DUPLICATE_BODY_PARAMETER
    )
    assert result.has_type(
        HPPIndicatorType.CONFLICTING_VALUES
    )


def test_duplicate_body_same_value(analyzer):
    result = analyzer.analyze(
        body="id=1&id=1"
    )

    assert result.has_type(
        HPPIndicatorType.DUPLICATE_BODY_PARAMETER
    )
    assert not result.has_type(
        HPPIndicatorType.CONFLICTING_VALUES
    )


def test_bytes_body(analyzer):
    result = analyzer.analyze(
        body=b"role=user&role=admin"
    )

    assert result.detected
    assert result.has_type(
        HPPIndicatorType.DUPLICATE_BODY_PARAMETER
    )


def test_url_query_and_params(analyzer):
    result = analyzer.analyze(
        url="https://example.com/?id=1&id=2",
        params={"role": ["user", "admin"]},
    )

    assert result.has_type(
        HPPIndicatorType.DUPLICATE_QUERY_PARAMETER
    )
    assert result.has_type(
        HPPIndicatorType.DUPLICATE_PARAMETER
    )


def test_blank_query_values(analyzer):
    result = analyzer.analyze(
        url="https://example.com/?id=&id=2"
    )

    assert result.has_type(
        HPPIndicatorType.DUPLICATE_QUERY_PARAMETER
    )
    assert result.has_type(
        HPPIndicatorType.CONFLICTING_VALUES
    )


def test_encoded_parameter_name(analyzer):
    result = analyzer.analyze(
        url="https://example.com/?user%5Bid%5D=1&user%5Bid%5D=2"
    )

    assert result.has_type(
        HPPIndicatorType.DUPLICATE_QUERY_PARAMETER
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"url": 123},
        {"params": "invalid"},
        {"body": 123},
        {"method": 123},
    ],
)
def test_invalid_types(analyzer, kwargs):
    with pytest.raises(TypeError):
        analyzer.analyze(**kwargs)


def test_method_is_accepted(analyzer):
    result = analyzer.analyze(
        method="POST",
        body="id=1&id=2",
    )

    assert result.detected


def test_multiple_duplicate_parameters(analyzer):
    result = analyzer.analyze(
        url="https://example.com/?id=1&id=2&role=user&role=admin"
    )

    assert result.count >= 4
    assert "id" in result.names
    assert "role" in result.names


def test_types_are_unique(analyzer):
    result = analyzer.analyze(
        url="https://example.com/?id=1&id=2"
    )

    assert result.types.count(
        HPPIndicatorType.DUPLICATE_QUERY_PARAMETER
    ) == 1
