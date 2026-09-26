import pytest

from m_hunter.analyzers.ldap_injection import (
    LDAPInjectionAnalysis,
    LDAPInjectionAnalyzer,
    LDAPInjectionIndicatorType,
)


@pytest.fixture
def analyzer():
    return LDAPInjectionAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()

    assert isinstance(result, LDAPInjectionAnalysis)
    assert result.detected is False
    assert result.count == 0
    assert result.types == set()
    assert result.names == set()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ldap", LDAPInjectionIndicatorType.LDAP_PARAMETER),
        ("ldap_filter", LDAPInjectionIndicatorType.FILTER_PARAMETER),
        ("filter", LDAPInjectionIndicatorType.FILTER_PARAMETER),
        ("search", LDAPInjectionIndicatorType.SEARCH_PARAMETER),
        ("search_filter", LDAPInjectionIndicatorType.SEARCH_PARAMETER),
        ("dn", LDAPInjectionIndicatorType.LDAP_PARAMETER),
        ("uid", LDAPInjectionIndicatorType.LDAP_PARAMETER),
    ],
)
def test_ldap_parameters(analyzer, name, expected):
    result = analyzer.analyze(
        params={name: "value"}
    )

    assert result.has_type(expected)
    assert name in result.names


def test_ldap_marker(analyzer):
    result = analyzer.analyze(
        params={"ldapSearch": "value"}
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.LDAP_MARKER
    )


@pytest.mark.parametrize(
    "value",
    [
        "(uid=admin)",
        "(objectClass=*)",
        "(&(uid=admin)(role=user))",
        "(|(uid=admin)(uid=test))",
        "(!(uid=guest))",
    ],
)
def test_filter_syntax(analyzer, value):
    result = analyzer.analyze(
        params={"filter": value}
    )

    assert result.detected
    assert result.has_type(
        LDAPInjectionIndicatorType.GROUPING_OPERATOR
    )
    assert result.has_type(
        LDAPInjectionIndicatorType.ATTRIBUTE_OPERATOR
    )


def test_wildcard(analyzer):
    result = analyzer.analyze(
        params={"filter": "*"}
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.WILDCARD
    )


@pytest.mark.parametrize(
    "value",
    [
        "(&(uid=test))",
        "(|(uid=test))",
        "(!(uid=test))",
    ],
)
def test_logical_operators(analyzer, value):
    result = analyzer.analyze(
        params={"filter": value}
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.LOGICAL_OPERATOR
    )


@pytest.mark.parametrize(
    "value",
    [
        "(uid=test)",
        "(uid~=test)",
        "(uid>=test)",
        "(uid<=test)",
    ],
)
def test_attribute_operators(analyzer, value):
    result = analyzer.analyze(
        params={"filter": value}
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.ATTRIBUTE_OPERATOR
    )


@pytest.mark.parametrize(
    "value",
    [
        r"\2a",
        r"\28",
        r"\29",
        r"\5c",
        r"\00",
    ],
)
def test_escape_sequences(analyzer, value):
    result = analyzer.analyze(
        params={"filter": value}
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.LDAP_ESCAPE_SEQUENCE
    )


def test_ldap_query(analyzer):
    result = analyzer.analyze(
        ldap_query="(&(uid=admin)(objectClass=*))"
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.USER_CONTROLLED_FILTER
    )
    assert result.has_type(
        LDAPInjectionIndicatorType.FILTER_SYNTAX
    )


def test_user_controlled_filter(analyzer):
    result = analyzer.analyze(
        user_controlled_filter=True
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.USER_CONTROLLED_FILTER
    )


def test_response_ldap_error(analyzer):
    result = analyzer.analyze(
        response_body="LDAPException: invalid filter"
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.LDAP_ERROR
    )


def test_response_ldap_result(analyzer):
    result = analyzer.analyze(
        response_body="objectClass: user\ndistinguishedName: uid=test"
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.LDAP_RESULT
    )


def test_url_analysis(analyzer):
    result = analyzer.analyze(
        url="https://example.com/search?filter=%28uid%3D%2A%29"
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.WILDCARD
    )


def test_body_analysis(analyzer):
    result = analyzer.analyze(
        body="filter=(&(uid=test)(role=user))"
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.FILTER_SYNTAX
    )


def test_headers_analysis(analyzer):
    result = analyzer.analyze(
        headers={"X-LDAP-Filter": "(uid=test)"}
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.FILTER_SYNTAX
    )


def test_parameter_names(analyzer):
    result = analyzer.analyze(
        parameter_names=["ldap_filter"]
    )

    assert result.has_type(
        LDAPInjectionIndicatorType.LDAP_MARKER
    )


@pytest.mark.parametrize(
    "bad_url",
    [123, [], {}],
)
def test_invalid_url(analyzer, bad_url):
    with pytest.raises(TypeError):
        analyzer.analyze(url=bad_url)


@pytest.mark.parametrize(
    "bad_params",
    [[], "params", 123],
)
def test_invalid_params(analyzer, bad_params):
    with pytest.raises(TypeError):
        analyzer.analyze(params=bad_params)


@pytest.mark.parametrize(
    "bad_body",
    [123, [], {}],
)
def test_invalid_body(analyzer, bad_body):
    with pytest.raises(TypeError):
        analyzer.analyze(body=bad_body)


@pytest.mark.parametrize(
    "bad_headers",
    [[], "headers", 123],
)
def test_invalid_headers(analyzer, bad_headers):
    with pytest.raises(TypeError):
        analyzer.analyze(headers=bad_headers)


@pytest.mark.parametrize(
    "bad_response",
    [123, [], {}],
)
def test_invalid_response_body(analyzer, bad_response):
    with pytest.raises(TypeError):
        analyzer.analyze(response_body=bad_response)


@pytest.mark.parametrize(
    "bad_names",
    ["names", {}, 123],
)
def test_invalid_parameter_names(analyzer, bad_names):
    with pytest.raises(TypeError):
        analyzer.analyze(parameter_names=bad_names)


@pytest.mark.parametrize(
    "bad_query",
    [123, [], {}],
)
def test_invalid_ldap_query(analyzer, bad_query):
    with pytest.raises(TypeError):
        analyzer.analyze(ldap_query=bad_query)


@pytest.mark.parametrize(
    "bad_value",
    ["true", 1, [], {}],
)
def test_invalid_user_controlled_filter(analyzer, bad_value):
    with pytest.raises(TypeError):
        analyzer.analyze(user_controlled_filter=bad_value)
