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
                data = stream.read(4096)
                if not data:
                    break
                chunks.append(data)

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

        try:
            process.wait(
                timeout=resolved_timeout
            )

            stdout_thread.join()
            stderr_thread.join()

            duration = time.perf_counter() - start

            return ToolResult(
                command=normalized_command,
                return_code=process.returncode,
                stdout=b"".join(
                    stdout_chunks
                ).decode(
                    "utf-8",
                    errors="replace",
                ),
                stderr=b"".join(
                    stderr_chunks
                ).decode(
                    "utf-8",
                    errors="replace",
                ),
                duration=duration,
            )

        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

            stdout_thread.join()
            stderr_thread.join()

            duration = time.perf_counter() - start

            return ToolResult(
                command=normalized_command,
                return_code=None,
                stdout=b"".join(
                    stdout_chunks
                ).decode(
                    "utf-8",
                    errors="replace",
                ),
                stderr=b"".join(
                    stderr_chunks
                ).decode(
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
