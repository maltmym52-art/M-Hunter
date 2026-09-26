import pytest

from m_hunter.analyzers.idor import (
    IDORAnalysis,
    IDORAnalyzer,
    IDORIndicatorType,
)


@pytest.fixture
def analyzer():
    return IDORAnalyzer()


def test_empty_request_clean(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/",
    )

    assert isinstance(result, IDORAnalysis)
    assert result.detected is False
    assert result.count == 0


def test_object_id_parameter(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource",
        params={"id": "123"},
    )

    assert result.detected
    assert result.has_type(IDORIndicatorType.OBJECT_IDENTIFIER)
    assert result.has_type(IDORIndicatorType.RESOURCE_PARAMETER)


def test_user_id_parameter(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/profile",
        params={"user_id": "42"},
    )

    assert result.has_type(IDORIndicatorType.USER_IDENTIFIER)


def test_account_id_parameter(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/account",
        params={"account_id": "42"},
    )

    assert result.has_type(IDORIndicatorType.ACCOUNT_IDENTIFIER)


def test_document_id_parameter(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/document",
        params={"document_id": "42"},
    )

    assert result.has_type(IDORIndicatorType.DOCUMENT_IDENTIFIER)


def test_file_id_parameter(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/file",
        params={"file_id": "42"},
    )

    assert result.has_type(IDORIndicatorType.FILE_IDENTIFIER)


def test_order_id_parameter(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/orders",
        params={"order_id": "42"},
    )

    assert result.has_type(IDORIndicatorType.ORDER_IDENTIFIER)


def test_invoice_id_parameter(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/invoices",
        params={"invoice_id": "42"},
    )

    assert result.has_type(IDORIndicatorType.INVOICE_IDENTIFIER)


def test_project_id_parameter(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/projects",
        params={"project_id": "42"},
    )

    assert result.has_type(IDORIndicatorType.PROJECT_IDENTIFIER)


def test_query_parameter_detected(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource?id=123",
    )

    assert result.has_type(IDORIndicatorType.RESOURCE_PARAMETER)
    assert result.has_type(IDORIndicatorType.OBJECT_IDENTIFIER)


def test_numeric_identifier(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource",
        params={"id": "123"},
    )

    assert result.has_type(IDORIndicatorType.NUMERIC_IDENTIFIER)


def test_uuid_identifier(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource",
        params={
            "id": "550e8400-e29b-41d4-a716-446655440000"
        },
    )

    assert result.has_type(IDORIndicatorType.UUID_IDENTIFIER)


def test_user_path(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/users/123",
    )

    assert result.has_type(IDORIndicatorType.USER_IDENTIFIER)
    assert result.has_type(IDORIndicatorType.RESOURCE_PATH)


def test_account_path(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/accounts/123",
    )

    assert result.has_type(IDORIndicatorType.ACCOUNT_IDENTIFIER)


def test_document_path(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/documents/123",
    )

    assert result.has_type(IDORIndicatorType.DOCUMENT_IDENTIFIER)


def test_file_path(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/files/123",
    )

    assert result.has_type(IDORIndicatorType.FILE_IDENTIFIER)


def test_order_path(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/orders/123",
    )

    assert result.has_type(IDORIndicatorType.ORDER_IDENTIFIER)


def test_api_path(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/api/users/123",
    )

    assert result.has_type(IDORIndicatorType.API_RESOURCE)


def test_authorization_context(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource?id=123",
        headers={"Authorization": "Bearer token"},
    )

    assert result.has_type(
        IDORIndicatorType.AUTHENTICATION_CONTEXT
    )


def test_session_context(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource?id=123",
        cookies={"session": "abc"},
    )

    assert result.has_type(IDORIndicatorType.SESSION_CONTEXT)


def test_both_auth_contexts(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource?id=123",
        headers={"Authorization": "Bearer token"},
        cookies={"session": "abc"},
    )

    assert result.has_type(
        IDORIndicatorType.AUTHENTICATION_CONTEXT
    )
    assert result.has_type(
        IDORIndicatorType.SESSION_CONTEXT
    )


def test_case_insensitive_parameter(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource",
        params={"USER_ID": "123"},
    )

    assert result.has_type(IDORIndicatorType.USER_IDENTIFIER)


def test_multiple_parameters(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource",
        params={
            "user_id": "10",
            "document_id": "20",
        },
    )

    assert result.has_type(IDORIndicatorType.USER_IDENTIFIER)
    assert result.has_type(
        IDORIndicatorType.DOCUMENT_IDENTIFIER
    )


def test_duplicate_query_and_params_are_deduplicated(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource?id=123",
        params={"id": "123"},
    )

    values = [
        indicator.value
        for indicator in result.indicators
        if indicator.type == IDORIndicatorType.RESOURCE_PARAMETER
    ]

    assert len(values) == 1


def test_invalid_uuid_not_detected_as_uuid(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource",
        params={"id": "550e8400-invalid"},
    )

    assert not result.has_type(
        IDORIndicatorType.UUID_IDENTIFIER
    )


def test_non_numeric_identifier(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource",
        params={"id": "abc"},
    )

    assert result.has_type(IDORIndicatorType.OBJECT_IDENTIFIER)
    assert not result.has_type(
        IDORIndicatorType.NUMERIC_IDENTIFIER
    )


def test_empty_method_rejected(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            method="",
            url="https://example.com/",
        )


def test_empty_url_rejected(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            method="GET",
            url="",
        )


def test_indicator_names(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource?id=123",
    )

    assert "resource_parameter" in result.names
    assert "numeric_identifier" in result.names


def test_indicator_count_matches(analyzer):
    result = analyzer.analyze(
        method="GET",
        url="https://example.com/resource?id=123",
    )

    assert result.count == len(result.indicators)
