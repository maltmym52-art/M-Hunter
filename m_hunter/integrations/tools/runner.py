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
            raise ValueError(
                "command must not be empty"
            )

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

        try:
            process = subprocess.run(
                normalized_command,
                capture_output=True,
                text=True,
                timeout=resolved_timeout,
                cwd=cwd,
                env=env,
                shell=False,
                check=False,
            )

            duration = time.perf_counter() - start

            return ToolResult(
                command=normalized_command,
                return_code=process.returncode,
                stdout=process.stdout,
                stderr=process.stderr,
                duration=duration,
            )

        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - start

            stdout = exc.stdout or ""
            stderr = exc.stderr or ""

            if isinstance(stdout, bytes):
                stdout = stdout.decode(
                    "utf-8",
                    errors="replace",
                )

            if isinstance(stderr, bytes):
                stderr = stderr.decode(
                    "utf-8",
                    errors="replace",
                )

            return ToolResult(
                command=normalized_command,
                return_code=None,
                stdout=stdout,
                stderr=stderr,
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
