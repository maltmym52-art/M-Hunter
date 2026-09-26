from m_hunter.analyzers.nosql_injection import (
    NoSQLInjectionAnalyzer,
    NoSQLInjectionIndicatorType,
)


def analyzer():
    return NoSQLInjectionAnalyzer()


def test_clean_request():
    result = analyzer().analyze(
        "https://example.com/login",
        query={"username": "test"},
    )

    assert result.detected is False
    assert result.count == 0


def test_mongodb_eq_operator():
    result = analyzer().analyze(
        "https://example.com/login",
        query={"$eq": "admin"},
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.MONGODB_OPERATOR
    )


def test_mongodb_ne_operator():
    result = analyzer().analyze(
        "https://example.com/login",
        query={"$ne": "invalid"},
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.MONGODB_OPERATOR
    )


def test_regex_operator():
    result = analyzer().analyze(
        "https://example.com/search",
        query={"$regex": ".*"},
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.REGEX_OPERATOR
    )


def test_javascript_where_operator():
    result = analyzer().analyze(
        "https://example.com/search",
        query={"$where": "this.role == 'admin'"},
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.JAVASCRIPT_OPERATOR
    )


def test_unknown_dollar_operator():
    result = analyzer().analyze(
        "https://example.com/search",
        query={"$custom": "value"},
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.DOLLAR_PREFIX
    )


def test_dot_notation():
    result = analyzer().analyze(
        "https://example.com",
        query={"user.role": "admin"},
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.DOT_NOTATION
    )


def test_nested_query_object():
    result = analyzer().analyze(
        "https://example.com",
        query={"user": {"role": "admin"}},
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.QUERY_OBJECT
    )


def test_json_context():
    result = analyzer().analyze(
        "https://example.com/api/login",
        content_type="application/json; charset=utf-8",
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.JSON_OPERATOR
    )


def test_database_error_marker():
    result = analyzer().analyze(
        "https://example.com/login",
        response_text="MongoServerError: unknown operator",
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.DATABASE_ERROR
    )


def test_mongodb_context():
    result = analyzer().analyze(
        "https://example.com",
        response_text="mongoose Cast to ObjectId failed",
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.MONGODB_CONTEXT
    )


def test_url_operator_detection():
    result = analyzer().analyze(
        "https://example.com/search?$regex=.*",
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.MONGODB_OPERATOR
    )


def test_multiple_indicators():
    result = analyzer().analyze(
        "https://example.com/search",
        query={
            "$ne": "x",
            "$regex": ".*",
            "user.role": "admin",
            "profile": {"name": "test"},
        },
        content_type="application/json",
        response_text="MongoServerError",
    )

    assert result.detected
    assert result.count >= 5
    assert len(result.types) >= 5


def test_has_type_false():
    result = analyzer().analyze(
        "https://example.com",
        query={"name": "test"},
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.MONGODB_OPERATOR
    ) is False


def test_indicator_metadata():
    result = analyzer().analyze(
        "https://example.com",
        query={"$ne": "x"},
    )

    indicator = result.indicators[0]

    assert indicator.name == "$ne"
    assert indicator.value == "x"
    assert indicator.type == (
        NoSQLInjectionIndicatorType.MONGODB_OPERATOR
    )
    assert indicator.evidence


def test_types_are_unique():
    result = analyzer().analyze(
        "https://example.com",
        query={
            "$eq": "x",
            "$ne": "y",
            "$gt": "z",
        },
    )

    assert len(result.types) == len(set(result.types))


def test_names_are_unique():
    result = analyzer().analyze(
        "https://example.com",
        query={"$ne": "x"},
    )

    assert len(result.names) == len(set(result.names))


def test_empty_body_is_ignored():
    result = analyzer().analyze(
        "https://example.com",
        body=None,
    )

    assert result.detected is False


def test_content_type_is_normalized():
    result = analyzer().analyze(
        "https://example.com",
        content_type="APPLICATION/JSON; charset=UTF-8",
    )

    assert result.has_type(
        NoSQLInjectionIndicatorType.JSON_OPERATOR
    )


def test_indicator_count_matches_list():
    result = analyzer().analyze(
        "https://example.com",
        query={"$ne": "x"},
        response_text="MongoDB",
    )

    assert result.count == len(result.indicators)
