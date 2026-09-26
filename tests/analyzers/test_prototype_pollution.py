from m_hunter.analyzers.prototype_pollution import (
    PrototypePollutionAnalyzer,
    PrototypePollutionIndicatorType,
)


def analyzer():
    return PrototypePollutionAnalyzer()


def test_clean_request():
    result = analyzer().analyze(
        "https://example.com/profile",
        query={"name": "mohammed"},
    )
    assert result.detected is False
    assert result.count == 0


def test_proto_key_in_query():
    result = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )
    assert result.detected
    assert result.has_type(PrototypePollutionIndicatorType.PROTO_KEY)


def test_constructor_key_in_query():
    result = analyzer().analyze(
        "https://example.com",
        query={"constructor": "prototype"},
    )
    assert result.has_type(PrototypePollutionIndicatorType.CONSTRUCTOR_KEY)


def test_prototype_key_in_query():
    result = analyzer().analyze(
        "https://example.com",
        query={"prototype": "polluted"},
    )
    assert result.has_type(PrototypePollutionIndicatorType.PROTOTYPE_KEY)


def test_nested_object():
    result = analyzer().analyze(
        "https://example.com",
        body={"user": {"role": "admin"}},
    )
    assert result.has_type(PrototypePollutionIndicatorType.NESTED_OBJECT)


def test_json_body():
    result = analyzer().analyze(
        "https://example.com",
        body={"name": "test"},
    )
    assert result.has_type(PrototypePollutionIndicatorType.JSON_OBJECT)


def test_javascript_context():
    result = analyzer().analyze(
        "https://example.com/app.js",
        content_type="application/javascript; charset=utf-8",
    )
    assert result.has_type(PrototypePollutionIndicatorType.JAVASCRIPT_CONTEXT)


def test_pollution_marker():
    result = analyzer().analyze(
        "https://example.com",
        response_text="The object was polluted",
    )
    assert result.has_type(PrototypePollutionIndicatorType.POLLUTION_MARKER)


def test_url_proto_indicator():
    result = analyzer().analyze(
        "https://example.com/?__proto__=polluted",
    )
    assert result.has_type(PrototypePollutionIndicatorType.PROTO_KEY)


def test_multiple_indicators():
    result = analyzer().analyze(
        "https://example.com/?__proto__=polluted",
        query={"constructor": "prototype"},
        body={"user": {"role": "admin"}},
        content_type="application/javascript",
        response_text="polluted",
    )

    assert result.detected
    assert result.count >= 5
    assert len(result.types) >= 5


def test_has_type_false_for_missing_type():
    result = analyzer().analyze(
        "https://example.com",
        query={"name": "test"},
    )
    assert result.has_type(PrototypePollutionIndicatorType.PROTO_KEY) is False


def test_indicator_metadata():
    result = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )

    indicator = result.indicators[0]

    assert indicator.name == "__proto__"
    assert indicator.value == "polluted"
    assert indicator.type == PrototypePollutionIndicatorType.PROTO_KEY
    assert indicator.evidence


def test_types_are_unique():
    result = analyzer().analyze(
        "https://example.com",
        query={
            "__proto__": "a",
            "constructor": "b",
            "prototype": "c",
        },
    )

    assert len(result.types) == len(set(result.types))


def test_names_are_unique():
    result = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "a"},
    )

    assert len(result.names) == len(set(result.names))


def test_empty_body_is_not_json_object():
    result = analyzer().analyze(
        "https://example.com",
        body=None,
    )
    assert result.has_type(PrototypePollutionIndicatorType.JSON_OBJECT) is False


def test_content_type_parameters_are_normalized():
    result = analyzer().analyze(
        "https://example.com/app.js",
        content_type="text/javascript; charset=UTF-8",
    )
    assert result.has_type(PrototypePollutionIndicatorType.JAVASCRIPT_CONTEXT)


def test_case_insensitive_keys():
    result = analyzer().analyze(
        "https://example.com",
        query={"__PROTO__": "polluted"},
    )
    assert result.has_type(PrototypePollutionIndicatorType.PROTO_KEY)


def test_case_insensitive_response_marker():
    result = analyzer().analyze(
        "https://example.com",
        response_text="POLLUTED",
    )
    assert result.has_type(PrototypePollutionIndicatorType.POLLUTION_MARKER)


def test_regular_nested_object_does_not_use_prototype_type():
    result = analyzer().analyze(
        "https://example.com",
        body={"profile": {"name": "test"}},
    )
    assert result.has_type(PrototypePollutionIndicatorType.PROTOTYPE_KEY) is False


def test_indicator_count_matches_list():
    result = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
        body={"user": {"name": "test"}},
    )
    assert result.count == len(result.indicators)


def test_analysis_names_include_sources():
    result = analyzer().analyze(
        "https://example.com",
        query={"__proto__": "polluted"},
    )
    assert "__proto__" in result.names
