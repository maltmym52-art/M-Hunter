import pytest

from m_hunter.analyzers.xxe import (
    XXEAnalysis,
    XXEAnalyzer,
    XXEIndicatorType,
)


@pytest.fixture
def analyzer():
    return XXEAnalyzer()


def test_empty_content(analyzer):
    result = analyzer.analyze("")

    assert isinstance(result, XXEAnalysis)
    assert result.detected is False
    assert result.indicator_count == 0
    assert result.types == []
    assert result.names == []
    assert result.indicators == []


def test_plain_xml_has_no_xxe_indicators(analyzer):
    result = analyzer.analyze(
        '<?xml version="1.0"?><root><item>hello</item></root>'
    )

    assert result.detected is False
    assert result.indicator_count == 0


def test_bytes_content_is_supported(analyzer):
    result = analyzer.analyze(
        b'<!DOCTYPE root><root>hello</root>'
    )

    assert result.detected is True
    assert result.doctype_detected is True


def test_invalid_content_type(analyzer):
    with pytest.raises(TypeError, match="content must be str or bytes"):
        analyzer.analyze(123)


def test_doctype_is_detected(analyzer):
    result = analyzer.analyze(
        "<!DOCTYPE root><root>hello</root>"
    )

    assert result.doctype_detected is True
    assert XXEIndicatorType.DOCTYPE_DECLARATION in result.types


def test_doctype_is_case_insensitive(analyzer):
    result = analyzer.analyze(
        "<!doctype root><root>hello</root>"
    )

    assert result.doctype_detected is True


def test_entity_declaration_is_detected(analyzer):
    result = analyzer.analyze(
        '<!DOCTYPE root [<!ENTITY test "hello">]>'
        "<root>&test;</root>"
    )

    assert result.entity_declaration_detected is True
    assert XXEIndicatorType.ENTITY_DECLARATION in result.types


def test_external_entity_is_detected(analyzer):
    result = analyzer.analyze(
        '<!DOCTYPE root ['
        '<!ENTITY test SYSTEM "http://example.invalid/test">'
        ']>'
        "<root>&test;</root>"
    )

    assert result.external_entity_detected is True
    assert XXEIndicatorType.EXTERNAL_ENTITY in result.types


def test_system_identifier_is_detected(analyzer):
    result = analyzer.analyze(
        '<!ENTITY test SYSTEM "http://example.invalid/test">'
    )

    assert XXEIndicatorType.SYSTEM_IDENTIFIER in result.types
    assert result.external_identifier_detected is True


def test_public_identifier_is_detected(analyzer):
    result = analyzer.analyze(
        '<!ENTITY test PUBLIC "-//Example//DTD Test//EN" '
        '"http://example.invalid/test.dtd">'
    )

    assert XXEIndicatorType.PUBLIC_IDENTIFIER in result.types
    assert result.external_identifier_detected is True


def test_entity_reference_is_detected(analyzer):
    result = analyzer.analyze(
        "<root>&test;</root>"
    )

    assert XXEIndicatorType.ENTITY_REFERENCE in result.types


def test_builtin_xml_entities_are_detected_as_references(analyzer):
    result = analyzer.analyze(
        "<root>&amp;&lt;&gt;&quot;&apos;</root>"
    )

    assert result.detected is True
    assert result.entity_reference_detected if hasattr(
        result, "entity_reference_detected"
    ) else XXEIndicatorType.ENTITY_REFERENCE in result.types


def test_multiple_indicators_are_collected(analyzer):
    content = (
        '<!DOCTYPE root ['
        '<!ENTITY first SYSTEM "http://example.invalid/a">'
        '<!ENTITY second PUBLIC "-//Example//DTD Test//EN" '
        '"http://example.invalid/b">'
        ']>'
        "<root>&first;&second;</root>"
    )

    result = analyzer.analyze(content)

    assert result.detected is True
    assert result.indicator_count >= 5
    assert len(result.indicators) == result.indicator_count
    assert result.types
    assert result.names


def test_indicator_positions_are_recorded(analyzer):
    content = "prefix <!DOCTYPE root><root>test</root>"

    result = analyzer.analyze(content)

    indicator = next(
        item
        for item in result.indicators
        if item.type == XXEIndicatorType.DOCTYPE_DECLARATION
    )

    assert indicator.position == content.index("<!DOCTYPE")


def test_indicator_evidence_is_preserved(analyzer):
    content = '<!ENTITY test SYSTEM "http://example.invalid/test">'

    result = analyzer.analyze(content)

    indicator = next(
        item
        for item in result.indicators
        if item.type == XXEIndicatorType.ENTITY_DECLARATION
    )

    assert "<!ENTITY test SYSTEM" in indicator.evidence


def test_no_duplicate_type_names(analyzer):
    result = analyzer.analyze(
        "<!DOCTYPE root><!DOCTYPE another><root>hello</root>"
    )

    assert result.names.count(
        XXEIndicatorType.DOCTYPE_DECLARATION.value
    ) == 1


def test_external_entity_requires_entity_declaration(analyzer):
    result = analyzer.analyze(
        '<!DOCTYPE root SYSTEM "http://example.invalid/root.dtd">'
    )

    assert result.doctype_detected is True
    assert result.external_identifier_detected is True


def test_local_file_identifier_is_detected_as_system_identifier(analyzer):
    result = analyzer.analyze(
        '<!ENTITY test SYSTEM "file:///tmp/example.txt">'
    )

    assert XXEIndicatorType.SYSTEM_IDENTIFIER in result.types


def test_http_external_identifier_is_detected(analyzer):
    result = analyzer.analyze(
        '<!ENTITY test SYSTEM "http://example.invalid/data">'
    )

    assert XXEIndicatorType.SYSTEM_IDENTIFIER in result.types


def test_https_external_identifier_is_detected(analyzer):
    result = analyzer.analyze(
        '<!ENTITY test SYSTEM "https://example.invalid/data">'
    )

    assert XXEIndicatorType.SYSTEM_IDENTIFIER in result.types


def test_indicator_engine_is_not_used(analyzer):
    result = analyzer.analyze(
        '<!DOCTYPE root><!ENTITY test "hello">'
    )

    assert all(
        not hasattr(indicator, "engine")
        for indicator in result.indicators
    )


def test_analysis_properties_are_consistent(analyzer):
    result = analyzer.analyze(
        '<!DOCTYPE root ['
        '<!ENTITY test SYSTEM "http://example.invalid/test">'
        ']>'
        "<root>&test;</root>"
    )

    assert result.detected is True
    assert result.indicator_count == len(result.indicators)
    assert result.doctype_detected is True
    assert result.entity_declaration_detected is True
    assert result.external_entity_detected is True
    assert result.external_identifier_detected is True


def test_regular_ampersand_text_is_not_entity_reference(analyzer):
    result = analyzer.analyze(
        "<root>Tom & Jerry</root>"
    )

    assert XXEIndicatorType.ENTITY_REFERENCE not in result.types


def test_malformed_entity_syntax_is_not_required_to_be_detected(analyzer):
    result = analyzer.analyze(
        "<root>&invalid</root>"
    )

    assert result.detected is False


def test_large_normal_xml_remains_safe(analyzer):
    content = "<root>" + ("<item>value</item>" * 100) + "</root>"

    result = analyzer.analyze(content)

    assert result.detected is False


def test_types_preserve_first_seen_order(analyzer):
    result = analyzer.analyze(
        '<!DOCTYPE root>'
        '<!ENTITY test SYSTEM "http://example.invalid/test">'
        "<root>&test;</root>"
    )

    assert result.types[0] == XXEIndicatorType.DOCTYPE_DECLARATION
    assert result.types[1] == XXEIndicatorType.ENTITY_DECLARATION
    assert result.types[2] == XXEIndicatorType.EXTERNAL_ENTITY
    assert result.types[3] == XXEIndicatorType.SYSTEM_IDENTIFIER
    assert result.types[4] == XXEIndicatorType.ENTITY_REFERENCE
