from dataclasses import dataclass
import shutil
import subprocess
import threading
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

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []

        def read_stream(stream, chunks):
            while True:
                line = stream.readline()
                if not line:
                    break
                chunks.append(line)

        stdout_thread = threading.Thread(
            target=read_stream,
            args=(process.stdout, stdout_chunks),
            daemon=True,
        )

        stderr_thread = threading.Thread(
            target=read_stream,
            args=(process.stderr, stderr_chunks),
            daemon=True,
        )

        stdout_thread.start()
        stderr_thread.start()

        timed_out = False

        try:
            process.wait(timeout=resolved_timeout)

        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()

        stdout_thread.join(timeout=1.0)
        stderr_thread.join(timeout=1.0)

        duration = time.perf_counter() - start

        stdout = b"".join(stdout_chunks)
        stderr = b"".join(stderr_chunks)

        return ToolResult(
            command=normalized_command,
            return_code=None if timed_out else process.returncode,
            stdout=stdout.decode(
                "utf-8",
                errors="replace",
            ),
            stderr=stderr.decode(
                "utf-8",
                errors="replace",
            ),
            duration=duration,
            timed_out=timed_out,
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
