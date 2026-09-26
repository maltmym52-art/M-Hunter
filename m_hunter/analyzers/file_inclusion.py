from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from m_hunter.core.response import HttpResponse


class FileInclusionIndicatorType(str, Enum):
    PATH_TRAVERSAL = "path_traversal"
    WINDOWS_PATH_TRAVERSAL = "windows_path_traversal"
    ABSOLUTE_UNIX_PATH = "absolute_unix_path"
    ABSOLUTE_WINDOWS_PATH = "absolute_windows_path"
    FILE_SCHEME = "file_scheme"
    PHP_WRAPPER = "php_wrapper"
    DATA_WRAPPER = "data_wrapper"
    HTTP_WRAPPER = "http_wrapper"
    REMOTE_URL = "remote_url"
    FILE_EXTENSION = "file_extension"
    SENSITIVE_FILE = "sensitive_file"
    FILE_INCLUDE_ERROR = "file_include_error"
    PHP_INCLUDE_ERROR = "php_include_error"
    PATH_NOT_FOUND_ERROR = "path_not_found_error"


@dataclass(frozen=True)
class FileInclusionIndicator:
    type: FileInclusionIndicatorType
    name: str
    value: str


@dataclass(frozen=True)
class FileInclusionAnalysis:
    detected: bool
    indicators: list[FileInclusionIndicator]

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> list[FileInclusionIndicatorType]:
        return [indicator.type for indicator in self.indicators]

    @property
    def names(self) -> list[str]:
        return [indicator.name for indicator in self.indicators]

    def has_type(self, indicator_type: FileInclusionIndicatorType) -> bool:
        return indicator_type in self.types


class FileInclusionAnalyzer:
    name = "file_inclusion"
    description = "Detects indicators associated with LFI/RFI and file inclusion behavior."

    _PATH_TRAVERSAL_MARKERS = (
        "../",
        "..\\",
        "%2e%2e%2f",
        "%2e%2e/",
        "%2e%2e%5c",
        "..%2f",
        "..%5c",
    )

    _SENSITIVE_FILES = (
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "boot.ini",
        "win.ini",
        "web.config",
    )

    _FILE_EXTENSIONS = (
        ".php",
        ".inc",
        ".conf",
        ".config",
        ".ini",
        ".log",
        ".txt",
        ".xml",
        ".json",
    )

    _FILE_INCLUDE_ERRORS = (
        "failed to open stream",
        "failed opening",
        "include(",
        "require(",
        "require_once(",
        "include_once(",
        "no such file or directory",
        "cannot open file",
        "cannot find the path",
        "file inclusion",
    )

    _PHP_INCLUDE_ERRORS = (
        "warning: include",
        "warning: require",
        "fatal error: require",
        "fatal error: include",
    )

    _PATH_NOT_FOUND_ERRORS = (
        "no such file or directory",
        "file not found",
        "path not found",
        "path was not found",
        "cannot find the path",
    )

    def analyze(
        self,
        response: HttpResponse,
        *,
        request_url: str | None = None,
        parameter_values: list[str] | None = None,
    ) -> FileInclusionAnalysis:
        indicators: list[FileInclusionIndicator] = []
        seen: set[tuple[FileInclusionIndicatorType, str]] = set()

        # Analyze URL path/query content without treating the normal
        # HTTP/HTTPS scheme or hostname as a remote-file indicator.
        parsed_response_url = urlsplit(response.url)
        sources = [
            parsed_response_url.path,
            parsed_response_url.query,
        ]

        if request_url:
            parsed_request_url = urlsplit(request_url)
            sources.extend(
                [
                    parsed_request_url.path,
                    parsed_request_url.query,
                ]
            )

        if parameter_values:
            sources.extend(parameter_values)

        text = response.text
        sources.append(text)

        def add(
            indicator_type: FileInclusionIndicatorType,
            name: str,
            value: str,
        ) -> None:
            key = (indicator_type, value)
            if key not in seen:
                seen.add(key)
                indicators.append(
                    FileInclusionIndicator(
                        type=indicator_type,
                        name=name,
                        value=value,
                    )
                )

        for source in sources:
            lowered = source.lower()

            for marker in self._PATH_TRAVERSAL_MARKERS:
                if marker in lowered:
                    add(
                        FileInclusionIndicatorType.PATH_TRAVERSAL,
                        "Path traversal",
                        marker,
                    )

            if "/etc/" in lowered:
                add(
                    FileInclusionIndicatorType.ABSOLUTE_UNIX_PATH,
                    "Absolute Unix path",
                    "/etc/",
                )

            if "c:\\" in lowered or "c:/" in lowered:
                add(
                    FileInclusionIndicatorType.ABSOLUTE_WINDOWS_PATH,
                    "Absolute Windows path",
                    "C:\\",
                )

            if "file://" in lowered:
                add(
                    FileInclusionIndicatorType.FILE_SCHEME,
                    "File URI scheme",
                    "file://",
                )

            for wrapper in ("php://filter", "php://input", "php://"):
                if wrapper in lowered:
                    add(
                        FileInclusionIndicatorType.PHP_WRAPPER,
                        "PHP stream wrapper",
                        wrapper,
                    )

            if "data://" in lowered:
                add(
                    FileInclusionIndicatorType.DATA_WRAPPER,
                    "Data stream wrapper",
                    "data://",
                )

            if "http://" in lowered or "https://" in lowered:
                add(
                    FileInclusionIndicatorType.HTTP_WRAPPER,
                    "HTTP stream wrapper",
                    "http:// or https://",
                )
                add(
                    FileInclusionIndicatorType.REMOTE_URL,
                    "Remote URL",
                    "http:// or https://",
                )

            for filename in self._SENSITIVE_FILES:
                if filename in lowered:
                    add(
                        FileInclusionIndicatorType.SENSITIVE_FILE,
                        "Sensitive file path",
                        filename,
                    )

            for extension in self._FILE_EXTENSIONS:
                if extension in lowered:
                    add(
                        FileInclusionIndicatorType.FILE_EXTENSION,
                        "File extension",
                        extension,
                    )

        for marker in self._FILE_INCLUDE_ERRORS:
            if marker.lower() in text.lower():
                add(
                    FileInclusionIndicatorType.FILE_INCLUDE_ERROR,
                    "File inclusion error",
                    marker,
                )

        for marker in self._PHP_INCLUDE_ERRORS:
            if marker.lower() in text.lower():
                add(
                    FileInclusionIndicatorType.PHP_INCLUDE_ERROR,
                    "PHP include/require error",
                    marker,
                )

        for marker in self._PATH_NOT_FOUND_ERRORS:
            if marker.lower() in text.lower():
                add(
                    FileInclusionIndicatorType.PATH_NOT_FOUND_ERROR,
                    "Path resolution error",
                    marker,
                )

        return FileInclusionAnalysis(
            detected=bool(indicators),
            indicators=indicators,
        )
