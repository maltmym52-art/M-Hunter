import pytest

from m_hunter.analyzers.command_injection import (
    CommandInjectionAnalysis,
    CommandInjectionAnalyzer,
    CommandInjectionIndicatorType,
)


@pytest.fixture
def analyzer():
    return CommandInjectionAnalyzer()


def test_empty_analysis(analyzer):
    result = analyzer.analyze()

    assert isinstance(result, CommandInjectionAnalysis)
    assert result.detected is False
    assert result.count == 0
    assert result.types == set()
    assert result.names == set()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("cmd", CommandInjectionIndicatorType.COMMAND_PARAMETER),
        ("command", CommandInjectionIndicatorType.COMMAND_PARAMETER),
        ("exec", CommandInjectionIndicatorType.EXECUTION_PARAMETER),
        ("execute", CommandInjectionIndicatorType.EXECUTION_PARAMETER),
        ("shell", CommandInjectionIndicatorType.SHELL_PARAMETER),
        ("shell_cmd", CommandInjectionIndicatorType.SHELL_PARAMETER),
        ("run", CommandInjectionIndicatorType.EXECUTION_PARAMETER),
    ],
)
def test_command_parameters(analyzer, name, expected):
    result = analyzer.analyze(
        params={name: "value"}
    )

    assert result.has_type(expected)
    assert name in result.names


@pytest.mark.parametrize(
    "value",
    [
        "value;test",
        "value&&test",
        "value||test",
    ],
)
def test_command_separators(analyzer, value):
    result = analyzer.analyze(
        params={"input": value}
    )

    assert result.has_type(
        CommandInjectionIndicatorType.COMMAND_SEPARATOR
    )


def test_pipe_operator(analyzer):
    result = analyzer.analyze(
        params={"input": "value|test"}
    )

    assert result.has_type(
        CommandInjectionIndicatorType.PIPE_OPERATOR
    )


@pytest.mark.parametrize(
    "value",
    [
        "value>test",
        "value>>test",
        "value<test",
    ],
)
def test_redirection_operators(analyzer, value):
    result = analyzer.analyze(
        params={"input": value}
    )

    assert result.has_type(
        CommandInjectionIndicatorType.REDIRECTION_OPERATOR
    )


@pytest.mark.parametrize(
    "value",
    [
        "$(test)",
        "${test}",
    ],
)
def test_command_substitution(analyzer, value):
    result = analyzer.analyze(
        params={"input": value}
    )

    assert result.has_type(
        CommandInjectionIndicatorType.COMMAND_SUBSTITUTION
    )


def test_backtick_substitution(analyzer):
    result = analyzer.analyze(
        params={"input": "`test`"}
    )

    assert result.has_type(
        CommandInjectionIndicatorType.BACKTICK_SUBSTITUTION
    )


def test_response_command_output(analyzer):
    result = analyzer.analyze(
        response_body="uid=1000(user) gid=1000(user)"
    )

    assert result.has_type(
        CommandInjectionIndicatorType.COMMAND_OUTPUT
    )


def test_response_execution_error(analyzer):
    result = analyzer.analyze(
        response_body="command not found"
    )

    assert result.has_type(
        CommandInjectionIndicatorType.COMMAND_OUTPUT
    )


def test_explicit_command_execution(analyzer):
    result = analyzer.analyze(
        command_execution=True
    )

    assert result.has_type(
        CommandInjectionIndicatorType.COMMAND_OUTPUT
    )


def test_explicit_time_delay(analyzer):
    result = analyzer.analyze(
        time_delay=True
    )

    assert result.has_type(
        CommandInjectionIndicatorType.TIME_DELAY_INDICATOR
    )


def test_parameter_names(analyzer):
    result = analyzer.analyze(
        parameter_names=["shell_command"]
    )

    assert result.has_type(
        CommandInjectionIndicatorType.COMMAND_MARKER
    )


def test_url_analysis(analyzer):
    result = analyzer.analyze(
        url="https://example.com/test?cmd=value%3Btest"
    )

    assert result.has_type(
        CommandInjectionIndicatorType.COMMAND_SEPARATOR
    )


def test_body_analysis(analyzer):
    result = analyzer.analyze(
        body="command=value|test"
    )

    assert result.has_type(
        CommandInjectionIndicatorType.PIPE_OPERATOR
    )


def test_headers_analysis(analyzer):
    result = analyzer.analyze(
        headers={"X-Test": "value;test"}
    )

    assert result.has_type(
        CommandInjectionIndicatorType.COMMAND_SEPARATOR
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
    "bad_value",
    ["true", 1, [], {}],
)
def test_invalid_command_execution(analyzer, bad_value):
    with pytest.raises(TypeError):
        analyzer.analyze(command_execution=bad_value)


@pytest.mark.parametrize(
    "bad_value",
    ["true", 1, [], {}],
)
def test_invalid_time_delay(analyzer, bad_value):
    with pytest.raises(TypeError):
        analyzer.analyze(time_delay=bad_value)
