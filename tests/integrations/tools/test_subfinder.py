from m_hunter.integrations.tools.runner import ToolResult
from m_hunter.integrations.tools.subfinder import SubfinderSource


class FakeRunner:
    def __init__(
        self,
        result=None,
        available=True,
    ):
        self.result = result
        self.available = available
        self.calls = []

    def run_if_available(
        self,
        executable,
        arguments=(),
        *,
        timeout=None,
        cwd=None,
        env=None,
    ):
        self.calls.append(
            {
                "executable": executable,
                "arguments": list(arguments),
                "timeout": timeout,
            }
        )

        if not self.available:
            return None

        return self.result


def make_result(
    stdout="",
    stderr="",
    return_code=0,
    timed_out=False,
):
    return ToolResult(
        command=(
            "subfinder",
            "-d",
            "example.com",
            "-silent",
        ),
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        duration=0.1,
        timed_out=timed_out,
    )


def test_source_name():
    source = SubfinderSource(
        runner=FakeRunner()
    )

    assert source.name == "subfinder"


def test_discover_subdomains():
    runner = FakeRunner(
        result=make_result(
            stdout=(
                "api.example.com\n"
                "admin.example.com\n"
                "www.example.com\n"
            )
        )
    )

    source = SubfinderSource(
        runner=runner
    )

    assets = source.discover(
        "example.com"
    )

    assert [
        asset.value
        for asset in assets
    ] == [
        "api.example.com",
        "admin.example.com",
        "www.example.com",
    ]

    assert all(
        asset.asset_type == "subdomain"
        for asset in assets
    )


def test_discovered_assets_record_source():
    runner = FakeRunner(
        result=make_result(
            stdout="api.example.com\n"
        )
    )

    source = SubfinderSource(
        runner=runner
    )

    assets = source.discover(
        "example.com"
    )

    assert assets[0].source == "subfinder"


def test_empty_lines_are_ignored():
    runner = FakeRunner(
        result=make_result(
            stdout=(
                "\n"
                "api.example.com\n"
                "\n"
                "   \n"
            )
        )
    )

    source = SubfinderSource(
        runner=runner
    )

    assets = source.discover(
        "example.com"
    )

    assert [
        asset.value
        for asset in assets
    ] == [
        "api.example.com",
    ]


def test_duplicate_subdomains_are_removed():
    runner = FakeRunner(
        result=make_result(
            stdout=(
                "api.example.com\n"
                "api.example.com\n"
                "www.example.com\n"
                "api.example.com\n"
            )
        )
    )

    source = SubfinderSource(
        runner=runner
    )

    assets = source.discover(
        "example.com"
    )

    assert [
        asset.value
        for asset in assets
    ] == [
        "api.example.com",
        "www.example.com",
    ]


def test_trailing_dot_is_removed():
    runner = FakeRunner(
        result=make_result(
            stdout=(
                "api.example.com.\n"
                "www.example.com.\n"
            )
        )
    )

    source = SubfinderSource(
        runner=runner
    )

    assets = source.discover(
        "example.com"
    )

    assert [
        asset.value
        for asset in assets
    ] == [
        "api.example.com",
        "www.example.com",
    ]


def test_target_is_trimmed():
    runner = FakeRunner(
        result=make_result(
            stdout="api.example.com\n"
        )
    )

    source = SubfinderSource(
        runner=runner
    )

    source.discover(
        "  example.com  "
    )

    assert runner.calls[0]["arguments"] == [
        "-d",
        "example.com",
        "-silent",
    ]


def test_runner_receives_configured_timeout():
    runner = FakeRunner(
        result=make_result(
            stdout="api.example.com\n"
        )
    )

    source = SubfinderSource(
        runner=runner,
        timeout=15.0,
    )

    source.discover(
        "example.com"
    )

    assert runner.calls[0]["timeout"] == 15.0


def test_missing_subfinder_returns_empty_list():
    runner = FakeRunner(
        available=False
    )

    source = SubfinderSource(
        runner=runner
    )

    assert source.discover(
        "example.com"
    ) == []


def test_nonzero_exit_code_returns_empty_list():
    runner = FakeRunner(
        result=make_result(
            stdout="api.example.com\n",
            stderr="subfinder error",
            return_code=1,
        )
    )

    source = SubfinderSource(
        runner=runner
    )

    assert source.discover(
        "example.com"
    ) == []


def test_timeout_returns_empty_list():
    runner = FakeRunner(
        result=make_result(
            stdout="api.example.com\n",
            timed_out=True,
        )
    )

    source = SubfinderSource(
        runner=runner
    )

    assert source.discover(
        "example.com"
    ) == []


def test_empty_target_is_rejected():
    runner = FakeRunner()

    source = SubfinderSource(
        runner=runner
    )

    try:
        source.discover("")
        assert False
    except ValueError as exc:
        assert str(exc) == "target must not be empty"


def test_whitespace_target_is_rejected():
    runner = FakeRunner()

    source = SubfinderSource(
        runner=runner
    )

    try:
        source.discover("   ")
        assert False
    except ValueError as exc:
        assert str(exc) == "target must not be empty"


def test_runner_receives_expected_executable():
    runner = FakeRunner(
        result=make_result(
            stdout="api.example.com\n"
        )
    )

    source = SubfinderSource(
        runner=runner
    )

    source.discover(
        "example.com"
    )

    assert runner.calls[0]["executable"] == "subfinder"


def test_runner_receives_silent_flag():
    runner = FakeRunner(
        result=make_result(
            stdout="api.example.com\n"
        )
    )

    source = SubfinderSource(
        runner=runner
    )

    source.discover(
        "example.com"
    )

    assert "-silent" in runner.calls[0]["arguments"]
