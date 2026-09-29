from dataclasses import dataclass
import os
import shutil
import signal
import subprocess
import threading
import time


def _windows_kernel32():
    """Load Windows process APIs with pointer-safe ctypes signatures."""
    import ctypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    kernel.CreateJobObjectW.restype = ctypes.c_void_p
    kernel.SetInformationJobObject.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint,
    ]
    kernel.SetInformationJobObject.restype = ctypes.c_int
    kernel.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel.AssignProcessToJobObject.restype = ctypes.c_int
    kernel.ResumeThread.argtypes = [ctypes.c_void_p]
    kernel.ResumeThread.restype = ctypes.c_uint
    kernel.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel.TerminateJobObject.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    return kernel


def _create_windows_kill_job():
    """Create a job that forcibly closes any descendants with the parent."""
    import ctypes
    from ctypes import wintypes

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel = _windows_kernel32()
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        return None
    limits = ExtendedLimitInformation()
    limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel.SetInformationJobObject(
        job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
    ):
        kernel.CloseHandle(job)
        return None
    return job


def _resume_windows_process(process) -> None:
    """Resume the suspended process's initial thread without private Popen fields."""
    import ctypes
    from ctypes import wintypes

    class ThreadEntry32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel = _windows_kernel32()
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel.Thread32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(ThreadEntry32)]
    kernel.Thread32First.restype = wintypes.BOOL
    kernel.Thread32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(ThreadEntry32)]
    kernel.Thread32Next.restype = wintypes.BOOL
    kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenThread.restype = ctypes.c_void_p

    snapshot = kernel.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = ThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        found = kernel.Thread32First(snapshot, ctypes.byref(entry))
        while found:
            if entry.th32OwnerProcessID == process.pid:
                thread = kernel.OpenThread(0x0002, False, entry.th32ThreadID)
                if thread:
                    try:
                        if kernel.ResumeThread(thread) == 0xFFFFFFFF:
                            raise ctypes.WinError(ctypes.get_last_error())
                        return
                    finally:
                        kernel.CloseHandle(thread)
            found = kernel.Thread32Next(snapshot, ctypes.byref(entry))
        raise ctypes.WinError(1168)  # ERROR_NOT_FOUND
    finally:
        kernel.CloseHandle(snapshot)


def _assign_windows_process_to_job(job, pid: int) -> bool:
    """Assign by PID using OpenProcess rather than Popen's private _handle."""
    import ctypes
    from ctypes import wintypes

    kernel = _windows_kernel32()
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = ctypes.c_void_p
    process_handle = kernel.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE
    if not process_handle:
        return False
    try:
        return bool(kernel.AssignProcessToJobObject(job, process_handle))
    finally:
        kernel.CloseHandle(process_handle)


def _prepare_windows_process(process, job):
    """Assign and resume a suspended process, closing/terminating on errors."""
    if job:
        try:
            assigned = _assign_windows_process_to_job(job, process.pid)
        except Exception:
            assigned = False
        if not assigned:
            _close_windows_job(job)
            job = None

    try:
        _resume_windows_process(process)
    except BaseException:
        try:
            process.kill()
            process.wait(timeout=5)
        finally:
            _close_windows_job(job)
        raise
    return job


def _close_windows_job(job) -> None:
    if job:
        _windows_kernel32().CloseHandle(job)


def _terminate_windows_job(job) -> bool:
    if not job:
        return False
    return bool(_windows_kernel32().TerminateJobObject(job, 1))


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
        return self.resolve(executable) is not None

    def resolve(self, executable: str) -> str | None:
        """Return the resolved executable path without executing it."""
        if not executable.strip():
            raise ValueError(
                "executable must not be empty"
            )

        return shutil.which(executable)

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

        popen_kwargs = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": False,
            "cwd": cwd,
            "env": env,
            "shell": False,
        }
        windows_job = None
        windows_suspended = False

        # External security tools may spawn child processes that inherit
        # stdout/stderr. Keep the whole process tree in a dedicated group
        # so a timeout can terminate the complete group and close pipes.
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        elif os.name == "nt":
            windows_job = _create_windows_kill_job()
            flags = subprocess.CREATE_NEW_PROCESS_GROUP
            if windows_job:
                flags |= 0x00000004  # CREATE_SUSPENDED
                windows_suspended = True
            popen_kwargs["creationflags"] = flags

        try:
            process = subprocess.Popen(normalized_command, **popen_kwargs)
        except BaseException:
            _close_windows_job(windows_job)
            raise

        if windows_suspended:
            windows_job = _prepare_windows_process(process, windows_job)

        timed_out = False

        try:
            stdout, stderr = process.communicate(
                timeout=resolved_timeout
            )

        except subprocess.TimeoutExpired as exc:
            timed_out = True

            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif os.name == "nt":
                if not _terminate_windows_job(windows_job):
                    termination = subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                    if termination.returncode and process.poll() is None:
                        process.kill()
            else:
                process.kill()

            remaining_stdout, remaining_stderr = process.communicate()

            stdout = (
                exc.output or b""
            ) + (
                remaining_stdout or b""
            )

            stderr = (
                exc.stderr or b""
            ) + (
                remaining_stderr or b""
            )
        except BaseException:
            if os.name == "nt":
                if not _terminate_windows_job(windows_job):
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                if process.poll() is None:
                    process.kill()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            raise
        finally:
            _close_windows_job(windows_job)

        duration = time.perf_counter() - start

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
