import sys
import time

import pytest

from m_hunter.integrations.tools.runner import (
    ToolResult,
    ToolRunner,
)


def test_tool_result_success():
    result = ToolResult(
        command=("python", "--version"),
        return_code=0,
        stdout="Python 3",
        stderr="",
        duration=0.1,
    )

    assert result.success is True
    assert result.timed_out is False


def test_tool_result_failure():
    result = ToolResult(
        command=("python", "test"),
        return_code=1,
        stdout="",
        stderr="error",
        duration=0.1,
    )

    assert result.success is False


def test_tool_result_timeout_is_failure():
    result = ToolResult(
        command=("python", "test"),
        return_code=None,
        stdout="",
        stderr="",
        duration=0.1,
        timed_out=True,
    )

    assert result.success is False


def test_runner_default_timeout():
    runner = ToolRunner()

    assert runner.default_timeout == 60.0


def test_runner_custom_timeout():
    runner = ToolRunner(
        default_timeout=10.0
    )

    assert runner.default_timeout == 10.0


def test_invalid_default_timeout():
    with pytest.raises(
        ValueError,
        match="default_timeout must be greater than 0",
    ):
        ToolRunner(default_timeout=0)


def test_is_available_for_existing_executable():
    runner = ToolRunner()

    assert runner.is_available(sys.executable) is True


def test_is_available_for_missing_executable():
    runner = ToolRunner()

    assert runner.is_available(
        "definitely-not-a-real-executable"
    ) is False


def test_empty_executable_is_rejected():
    runner = ToolRunner()

    with pytest.raises(
        ValueError,
        match="executable must not be empty",
    ):
        runner.is_available("")


def test_run_simple_command():
    runner = ToolRunner()

    result = runner.run(
        [
            sys.executable,
            "-c",
            "print('hello')",
        ]
    )

    assert result.command == (
        sys.executable,
        "-c",
        "print('hello')",
    )
    assert result.return_code == 0
    assert result.stdout.strip() == "hello"
    assert result.stderr == ""
    assert result.success is True
    assert result.duration >= 0


def test_run_failed_command():
    runner = ToolRunner()

    result = runner.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.exit(7)",
        ]
    )

    assert result.return_code == 7
    assert result.success is False


def test_run_captures_stderr():
    runner = ToolRunner()

    result = runner.run(
        [
            sys.executable,
            "-c",
            "import sys; print('error', file=sys.stderr)",
        ]
    )

    assert result.return_code == 0
    assert result.stderr.strip() == "error"


def test_run_accepts_tuple_command():
    runner = ToolRunner()

    result = runner.run(
        (
            sys.executable,
            "-c",
            "print('tuple')",
        )
    )

    assert result.success is True
    assert result.stdout.strip() == "tuple"


def test_empty_command_is_rejected():
    runner = ToolRunner()

    with pytest.raises(
        ValueError,
        match="command must not be empty",
    ):
        runner.run([])


def test_empty_executable_is_rejected():
    runner = ToolRunner()

    with pytest.raises(
        ValueError,
        match="executable must not be empty",
    ):
        runner.run([""])


def test_invalid_timeout_is_rejected():
    runner = ToolRunner()

    with pytest.raises(
        ValueError,
        match="timeout must be greater than 0",
    ):
        runner.run(
            [sys.executable, "-c", "print('x')"],
            timeout=0,
        )


def test_custom_timeout_is_used():
    runner = ToolRunner(
        default_timeout=10
    )

    result = runner.run(
        [
            sys.executable,
            "-c",
            "print('timeout')",
        ],
        timeout=2,
    )

    assert result.success is True


def test_command_is_not_executed_through_shell():
    runner = ToolRunner()

    result = runner.run(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            "hello;echo-not-executed",
        ]
    )

    assert result.success is True
    assert result.stdout.strip() == "hello;echo-not-executed"


def test_timeout_is_reported():
    runner = ToolRunner(
        default_timeout=0.1
    )

    result = runner.run(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(1)",
        ]
    )

    assert result.timed_out is True
    assert result.return_code is None
    assert result.success is False


def test_timeout_captures_partial_output():
    runner = ToolRunner(
        default_timeout=5.0
    )

    result = runner.run(
        [
            sys.executable,
            "-c",
            (
                "import sys,time; "
                "print('before-timeout'); "
                "sys.stdout.flush(); "
                "time.sleep(10)"
            ),
        ],
        timeout=5.0,
    )

    assert result.timed_out is True
    assert "before-timeout" in result.stdout


def test_run_if_available_existing_tool():
    runner = ToolRunner()

    result = runner.run_if_available(
        sys.executable,
        [
            "-c",
            "print('available')",
        ],
    )

    assert result is not None
    assert result.success is True
    assert result.stdout.strip() == "available"


def test_run_if_available_missing_tool():
    runner = ToolRunner()

    result = runner.run_if_available(
        "definitely-not-a-real-executable",
    )

    assert result is None


def test_run_if_available_passes_arguments():
    runner = ToolRunner()

    result = runner.run_if_available(
        sys.executable,
        [
            "-c",
            "print('argument-test')",
        ],
    )

    assert result is not None
    assert result.stdout.strip() == "argument-test"


def test_duration_is_recorded():
    runner = ToolRunner()

    start = time.perf_counter()

    result = runner.run(
        [
            sys.executable,
            "-c",
            "print('duration')",
        ]
    )

    elapsed = time.perf_counter() - start

    assert result.duration >= 0
    assert result.duration <= elapsed + 1


@pytest.mark.skipif(
    not hasattr(__import__("os"), "setsid"),
    reason="requires POSIX process groups",
)
def test_timeout_terminates_child_holding_output_pipe():
    runner = ToolRunner(default_timeout=0.5)

    result = runner.run(
        [
            sys.executable,
            "-c",
            (
                "import subprocess,sys,time; "
                "child=subprocess.Popen(["
                "sys.executable,'-c',"
                "'import time; time.sleep(30)'"
                "]); "
                "print('before-child-timeout', flush=True); "
                "time.sleep(30)"
            ),
        ],
        timeout=0.5,
    )

    assert result.timed_out is True
    assert result.return_code is None
    assert "before-child-timeout" in result.stdout
    assert result.duration < 5
