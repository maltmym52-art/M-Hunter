import pytest

from m_hunter.analyzers.deserialization import (
    DeserializationAnalysis,
    DeserializationAnalyzer,
    DeserializationIndicator,
    DeserializationIndicatorType,
)


@pytest.fixture
def analyzer():
    return DeserializationAnalyzer()


def test_clean_input_returns_no_detection(analyzer):
    result = analyzer.analyze()

    assert isinstance(result, DeserializationAnalysis)
    assert result.detected is False
    assert result.indicator_count == 0
    assert result.types == []
    assert result.names == []
    assert result.indicators == []


def test_serialized_java_content_type(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Type": "application/x-java-serialized-object"
        }
    )

    assert result.detected is True
    assert result.indicator_count == 1
    assert (
        DeserializationIndicatorType.SERIALIZED_CONTENT_TYPE
        in result.types
    )
    assert result.serialized_content_type_detected is True


def test_serialized_python_content_type(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Type": "application/x-python-serialized"
        }
    )

    assert result.serialized_content_type_detected is True


def test_serialized_ruby_content_type(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Type": "application/x-ruby-marshal"
        }
    )

    assert result.serialized_content_type_detected is True


def test_serialized_php_content_type(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Type": "application/vnd.php.serialized"
        }
    )

    assert result.serialized_content_type_detected is True


def test_content_type_parameters_are_accepted(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Type": (
                "application/x-java-serialized-object; charset=binary"
            )
        }
    )

    assert result.detected is True


def test_content_type_is_case_insensitive(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Type": "APPLICATION/X-JAVA-SERIALIZED-OBJECT"
        }
    )

    assert result.detected is True


def test_serialization_header(analyzer):
    result = analyzer.analyze(
        headers={
            "X-Java-Serialized-Object": "true"
        }
    )

    assert result.detected is True
    assert result.serialization_header_detected is True
    assert (
        DeserializationIndicatorType.SERIALIZATION_HEADER
        in result.types
    )


def test_multiple_serialization_headers(analyzer):
    result = analyzer.analyze(
        headers={
            "X-Java-Serialized-Object": "true",
            "X-Python-Pickle": "true",
        }
    )

    assert result.indicator_count == 2
    assert result.serialization_header_detected is True
    assert len(result.indicators) == 2


def test_serialized_parameter(analyzer):
    result = analyzer.analyze(
        parameters={
            "serialized": "data"
        }
    )

    assert result.detected is True
    assert result.serialized_parameter_detected is True
    assert "serialized" in result.names


def test_serialized_parameter_variants(analyzer):
    result = analyzer.analyze(
        parameters={
            "serialize": "data",
            "serialized_data": "data",
            "pickle": "data",
            "marshal": "data",
        }
    )

    assert result.serialized_parameter_detected is True
    assert result.indicator_count == 4


def test_parameter_names_are_case_insensitive(analyzer):
    result = analyzer.analyze(
        parameters={
            "Serialized_Data": "data"
        }
    )

    assert result.serialized_parameter_detected is True
    assert "serialized_data" in result.names


def test_serialized_cookie(analyzer):
    result = analyzer.analyze(
        cookies={
            "serialized": "data"
        }
    )

    assert result.detected is True
    assert result.serialized_cookie_detected is True
    assert "serialized" in result.names


def test_serialized_cookie_variants(analyzer):
    result = analyzer.analyze(
        cookies={
            "pickle": "data",
            "marshal": "data",
            "java_object": "data",
        }
    )

    assert result.serialized_cookie_detected is True
    assert result.indicator_count == 3


def test_cookie_names_are_case_insensitive(analyzer):
    result = analyzer.analyze(
        cookies={
            "JavaObject": "data"
        }
    )

    assert result.serialized_cookie_detected is True
    assert "javaobject" in result.names


def test_serialized_file_ser(analyzer):
    result = analyzer.analyze(
        filename="payload.ser"
    )

    assert result.detected is True
    assert result.serialized_file_detected is True


def test_serialized_file_pickle(analyzer):
    result = analyzer.analyze(
        filename="session.pkl"
    )

    assert result.serialized_file_detected is True


def test_serialized_file_marshal(analyzer):
    result = analyzer.analyze(
        filename="object.marshal"
    )

    assert result.serialized_file_detected is True


def test_serialized_file_class(analyzer):
    result = analyzer.analyze(
        filename="Object.class"
    )

    assert result.serialized_file_detected is True


def test_filename_matching_is_case_insensitive(analyzer):
    result = analyzer.analyze(
        filename="OBJECT.PICKLE"
    )

    assert result.serialized_file_detected is True


def test_non_serialized_file_is_ignored(analyzer):
    result = analyzer.analyze(
        filename="index.html"
    )

    assert result.detected is False


def test_multiple_indicator_types(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Type": "application/x-java-serialized-object",
            "X-Java-Serialized-Object": "true",
        },
        parameters={
            "serialized": "data",
        },
        cookies={
            "pickle": "data",
        },
        filename="object.ser",
    )

    assert result.detected is True
    assert result.indicator_count == 5
    assert len(result.types) == 5


def test_indicator_objects_have_correct_type(analyzer):
    result = analyzer.analyze(
        parameters={
            "pickle": "data"
        }
    )

    assert isinstance(result.indicators[0], DeserializationIndicator)
    assert (
        result.indicators[0].type
        == DeserializationIndicatorType.SERIALIZED_PARAMETER
    )


def test_indicator_contains_evidence(analyzer):
    result = analyzer.analyze(
        cookies={
            "serialized": "data"
        }
    )

    assert result.indicators[0].evidence
    assert "serialized" in result.indicators[0].evidence.lower()


def test_indicator_contains_name(analyzer):
    result = analyzer.analyze(
        parameters={
            "pickle": "data"
        }
    )

    assert result.indicators[0].name == "pickle"


def test_types_are_unique(analyzer):
    result = analyzer.analyze(
        parameters={
            "serialized": "one",
            "pickle": "two",
        }
    )

    assert result.types == [
        DeserializationIndicatorType.SERIALIZED_PARAMETER
    ]


def test_names_are_unique(analyzer):
    result = analyzer.analyze(
        parameters={
            "Serialized": "one",
            "serialized": "two",
        }
    )

    assert result.names == ["serialized"]


def test_header_whitespace_is_normalized(analyzer):
    result = analyzer.analyze(
        headers={
            "  Content-Type  ": (
                "  application/x-java-serialized-object  "
            )
        }
    )

    assert result.detected is True


def test_empty_header_values_do_not_create_false_positive(analyzer):
    result = analyzer.analyze(
        headers={
            "Content-Type": ""
        }
    )

    assert result.detected is False


def test_unrelated_parameter_is_ignored(analyzer):
    result = analyzer.analyze(
        parameters={
            "username": "admin"
        }
    )

    assert result.detected is False


def test_unrelated_cookie_is_ignored(analyzer):
    result = analyzer.analyze(
        cookies={
            "session": "abc123"
        }
    )

    assert result.detected is False


def test_none_filename_is_valid(analyzer):
    result = analyzer.analyze(filename=None)

    assert result.detected is False


def test_invalid_headers_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(headers=[])


def test_invalid_parameters_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(parameters=[])


def test_invalid_cookies_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(cookies=[])


def test_invalid_filename_type(analyzer):
    with pytest.raises(TypeError):
        analyzer.analyze(filename=123)


def test_detection_count_matches_indicators(analyzer):
    result = analyzer.analyze(
        headers={
            "X-Java-Serialized-Object": "true",
        },
        parameters={
            "pickle": "data",
        },
        cookies={
            "marshal": "data",
        },
        filename="object.ser",
    )

    assert result.indicator_count == len(result.indicators)
    assert result.indicator_count == 4
