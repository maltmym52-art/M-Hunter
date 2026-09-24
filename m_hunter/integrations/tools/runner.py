from dataclasses import dataclass
import shutil
import subprocess
import time


@dataclass(frozen=True)
class ToolResult:
    command: tuple[str, ...]
    return_code: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return (
            not self.timed_out
            and self.return_code == 0
        )


class ToolRunner:
    """Runs external security tools without invoking a shell."""

    def __init__(self, default_timeout: float = 60.0):
        if default_timeout <= 0:
            raise ValueError(
                "default_timeout must be greater than 0"
            )

        self.default_timeout = default_timeout

    def is_available(self, executable: str) -> bool:
        if not executable.strip():
            raise ValueError(
                "executable must not be empty"
            )

        return shutil.which(executable) is not None

    def run(
        self,
        command: list[str] | tuple[str, ...],
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ToolResult:
        if not command:
            raise ValueError("command must not be empty")

        normalized_command = tuple(
            str(argument)
            for argument in command
        )

        if not normalized_command[0].strip():
            raise ValueError(
                "executable must not be empty"
            )

        resolved_timeout = (
            self.default_timeout
            if timeout is None
            else timeout
        )

        if resolved_timeout <= 0:
            raise ValueError(
                "timeout must be greater than 0"
            )

        start = time.perf_counter()

        process = subprocess.Popen(
            normalized_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            cwd=cwd,
            env=env,
            shell=False,
        )

        try:
            stdout, stderr = process.communicate(
                timeout=resolved_timeout
            )

            duration = time.perf_counter() - start

            return ToolResult(
                command=normalized_command,
                return_code=process.returncode,
                stdout=stdout.decode(
                    "utf-8",
                    errors="replace",
                ),
                stderr=stderr.decode(
                    "utf-8",
                    errors="replace",
                ),
                duration=duration,
            )

        except subprocess.TimeoutExpired as exc:
            partial_stdout = exc.stdout or b""
            partial_stderr = exc.stderr or b""

            process.kill()

            remaining_stdout, remaining_stderr = (
                process.communicate()
            )

            if remaining_stdout:
                partial_stdout += remaining_stdout

            if remaining_stderr:
                partial_stderr += remaining_stderr

            duration = time.perf_counter() - start

            if isinstance(partial_stdout, str):
                partial_stdout = partial_stdout.encode()

            if isinstance(partial_stderr, str):
                partial_stderr = partial_stderr.encode()

            return ToolResult(
                command=normalized_command,
                return_code=None,
                stdout=partial_stdout.decode(
                    "utf-8",
                    errors="replace",
                ),
                stderr=partial_stderr.decode(
                    "utf-8",
                    errors="replace",
                ),
                duration=duration,
                timed_out=True,
            )

    def run_if_available(
        self,
        executable: str,
        arguments: list[str] | tuple[str, ...] = (),
        *,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ToolResult | None:
        if not self.is_available(executable):
            return None

        command = [
            executable,
            *arguments,
        ]

        return self.run(
            command,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
