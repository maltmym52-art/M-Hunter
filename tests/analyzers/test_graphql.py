import pytest

from m_hunter.analyzers.graphql import (
    GraphQLAnalysis,
    GraphQLAnalyzer,
    GraphQLIndicator,
    GraphQLIndicatorType,
)


@pytest.fixture
def analyzer():
    return GraphQLAnalyzer()


def test_empty_input_returns_clean_analysis(analyzer):
    result = analyzer.analyze()

    assert isinstance(result, GraphQLAnalysis)
    assert result.detected is False
    assert result.indicator_count == 0
    assert result.types == []
    assert result.names == []
    assert result.indicators == []


def test_introspection_enabled(analyzer):
    result = analyzer.analyze(
        introspection_enabled=True,
    )

    assert result.detected is True
    assert result.introspection_enabled is True
    assert (
        GraphQLIndicatorType.INTROSPECTION_ENABLED
        in result.types
    )


def test_query_operation_detected(analyzer):
    result = analyzer.analyze(
        "query GetUser { user { id name } }"
    )

    assert result.query_detected is True
    assert (
        GraphQLIndicatorType.QUERY_OPERATION
        in result.types
    )


def test_mutation_operation_detected(analyzer):
    result = analyzer.analyze(
        "mutation CreateUser { createUser { id } }"
    )

    assert result.mutation_detected is True


def test_subscription_operation_detected(analyzer):
    result = analyzer.analyze(
        "subscription Events { events { id } }"
    )

    assert result.subscription_detected is True


def test_operation_detection_is_case_insensitive(analyzer):
    result = analyzer.analyze(
        "MUTATION CreateUser { createUser { id } }"
    )

    assert result.mutation_detected is True


def test_alias_usage_detected(analyzer):
    result = analyzer.analyze(
        "query { first: user { id } }"
    )

    assert result.alias_detected is True
    assert (
        GraphQLIndicatorType.ALIAS_USAGE
        in result.types
    )


def test_batching_detected(analyzer):
    result = analyzer.analyze(
        batch_count=3,
    )

    assert result.batching_detected is True
    assert (
        GraphQLIndicatorType.BATCHING
        in result.types
    )


def test_single_request_is_not_batching(analyzer):
    result = analyzer.analyze(
        batch_count=1,
    )

    assert result.batching_detected is False


def test_deep_query_detected(analyzer):
    result = analyzer.analyze(
        max_depth=6,
    )

    assert result.deep_query_detected is True
    assert (
        GraphQLIndicatorType.DEEP_QUERY
        in result.types
    )


def test_depth_of_five_is_not_deep(analyzer):
    result = analyzer.analyze(
        max_depth=5,
    )

    assert result.deep_query_detected is False


def test_large_query_detected(analyzer):
    query = "x" * 5000

    result = analyzer.analyze(query)

    assert result.large_query_detected is True
    assert (
        GraphQLIndicatorType.LARGE_QUERY
        in result.types
    )


def test_query_below_large_threshold_is_clean(analyzer):
    query = "x" * 100

    result = analyzer.analyze(
        query,
        large_query_threshold=500,
    )

    assert result.large_query_detected is False


@pytest.mark.parametrize(
    "field",
    [
        "password",
        "secret",
        "token",
        "accessToken",
        "refreshToken",
        "authorization",
        "apiKey",
        "privateKey",
        "creditCard",
        "cardNumber",
        "ssn",
    ],
)
def test_sensitive_field_detection(analyzer, field):
    result = analyzer.analyze(
        f"query {{ user {{ {field} }} }}"
    )

    assert result.sensitive_field_detected is True
    assert (
        GraphQLIndicatorType.SENSITIVE_FIELD
        in result.types
    )


def test_sensitive_field_name_is_normalized(analyzer):
    result = analyzer.analyze(
        "query { user { accessToken } }"
    )

    assert "accesstoken" in result.names


def test_multiple_sensitive_fields_are_detected(analyzer):
    result = analyzer.analyze(
        "query { user { password token apiKey ssn } }"
    )

    assert result.sensitive_field_detected is True
    assert len(
        [
            indicator
            for indicator in result.indicators
            if indicator.type
            == GraphQLIndicatorType.SENSITIVE_FIELD
        ]
    ) == 4


def test_multiple_indicator_types(analyzer):
    result = analyzer.analyze(
        "mutation UpdateUser { user { password } }",
        introspection_enabled=True,
        batch_count=2,
        max_depth=8,
    )

    assert result.detected is True
    assert result.introspection_enabled is True
    assert result.mutation_detected is True
    assert result.batching_detected is True
    assert result.deep_query_detected is True
    assert result.sensitive_field_detected is True


def test_indicator_count_matches_indicators(analyzer):
    result = analyzer.analyze(
        "query { user { password } }",
        introspection_enabled=True,
        batch_count=2,
    )

    assert result.indicator_count == len(result.indicators)


def test_indicator_objects_are_correct_type(analyzer):
    result = analyzer.analyze(
        introspection_enabled=True,
    )

    assert isinstance(result.indicators[0], GraphQLIndicator)


def test_indicator_contains_evidence(analyzer):
    result = analyzer.analyze(
        introspection_enabled=True,
    )

    assert result.indicators[0].evidence
    assert "introspection" in (
        result.indicators[0].evidence.lower()
    )


def test_indicator_contains_name(analyzer):
    result = analyzer.analyze(
        "mutation CreateUser { createUser { id } }"
    )

    mutation_indicators = [
        indicator
        for indicator in result.indicators
        if indicator.type
        == GraphQLIndicatorType.MUTATION_OPERATION
    ]

    assert mutation_indicators[0].name == "mutation"


def test_types_are_unique(analyzer):
    result = analyzer.analyze(
        "query { user { password } }"
    )

    assert len(result.types) == len(set(result.types))


def test_names_are_unique(analyzer):
    result = analyzer.analyze(
        "query { user { password password } }"
    )

    assert len(result.names) == len(set(result.names))


def test_batch_count_must_be_positive(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(batch_count=0)


def test_negative_batch_count_is_rejected(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(batch_count=-1)


def test_negative_depth_is_rejected(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(max_depth=-1)


def test_invalid_large_query_threshold_is_rejected(analyzer):
    with pytest.raises(ValueError):
        analyzer.analyze(
            large_query_threshold=0
        )


def test_invalid_query_type_is_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(123)


def test_invalid_introspection_type_is_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            introspection_enabled="true"
        )


def test_invalid_batch_count_type_is_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(batch_count="2")


def test_invalid_depth_type_is_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(max_depth="6")


def test_invalid_threshold_type_is_rejected(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(
            large_query_threshold="5000"
        )


def test_query_keyword_in_field_name_can_be_detected(analyzer):
    result = analyzer.analyze(
        "queryName"
    )

    assert result.query_detected is True


def test_no_sensitive_field_false_positive_for_normal_user(analyzer):
    result = analyzer.analyze(
        "query { user { id name email } }"
    )

    assert result.sensitive_field_detected is False


def test_query_length_boundary(analyzer):
    query = "x" * 100

    result = analyzer.analyze(
        query,
        large_query_threshold=100,
    )

    assert result.large_query_detected is True


def test_introspection_property_matches_type(analyzer):
    result = analyzer.analyze(
        introspection_enabled=True,
    )

    assert (
        result.introspection_enabled
        == (
            GraphQLIndicatorType.INTROSPECTION_ENABLED
            in result.types
        )
    )


def test_all_boolean_properties_match_types(analyzer):
    result = analyzer.analyze(
        "mutation { user { password } }",
        introspection_enabled=True,
        batch_count=2,
        max_depth=10,
    )

    assert result.introspection_enabled
    assert result.mutation_detected
    assert result.batching_detected
    assert result.deep_query_detected
    assert result.sensitive_field_detected


def test_large_query_name_is_recorded(analyzer):
    result = analyzer.analyze(
        "x" * 100,
        large_query_threshold=10,
    )

    assert "query_length" in result.names


def test_batch_name_is_recorded(analyzer):
    result = analyzer.analyze(
        batch_count=2,
    )

    assert "batch" in result.names


def test_depth_name_is_recorded(analyzer):
    result = analyzer.analyze(
        max_depth=6,
    )

    assert "depth" in result.names
