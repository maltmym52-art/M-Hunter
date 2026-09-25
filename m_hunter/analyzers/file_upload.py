from dataclasses import dataclass, field
from enum import Enum
import re


class FileUploadIndicatorType(str, Enum):
    DANGEROUS_EXTENSION = "dangerous_extension"
    DOUBLE_EXTENSION = "double_extension"
    MIME_MISMATCH = "mime_mismatch"
    DANGEROUS_MIME = "dangerous_mime"
    EXECUTABLE_CONTENT_TYPE = "executable_content_type"
    UNSAFE_FILENAME = "unsafe_filename"


@dataclass(frozen=True)
class FileUploadIndicator:
    type: str
    evidence: str
    position: int = 0


@dataclass
class FileUploadAnalysis:
    indicators: list[FileUploadIndicator] = field(
        default_factory=list
    )

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def indicator_count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> list[str]:
        return list(
            dict.fromkeys(
                indicator.type
                for indicator in self.indicators
            )
        )

    @property
    def names(self) -> list[str]:
        return self.types


class FileUploadAnalyzer:
    """
    Detects file-upload security indicators from already collected
    filename and MIME metadata.

    This analyzer does not upload, execute, or modify files.
    """

    DANGEROUS_EXTENSIONS = {
        "php",
        "php3",
        "php4",
        "php5",
        "phtml",
        "phar",
        "jsp",
        "jspx",
        "asp",
        "aspx",
        "cgi",
        "pl",
        "py",
        "sh",
        "bash",
        "exe",
        "dll",
        "so",
    }

    DANGEROUS_MIME_TYPES = {
        "application/x-php",
        "application/x-httpd-php",
        "application/x-jsp",
        "application/x-sh",
        "application/x-shellscript",
        "application/x-executable",
        "application/x-msdownload",
    }

    EXECUTABLE_CONTENT_TYPES = {
        "application/x-php",
        "application/x-httpd-php",
        "application/x-jsp",
        "application/java-archive",
        "application/x-sh",
        "application/x-shellscript",
        "application/x-executable",
        "application/x-msdownload",
    }

    SAFE_EXTENSION_MIME = {
        "jpg": {
            "image/jpeg",
        },
        "jpeg": {
            "image/jpeg",
        },
        "png": {
            "image/png",
        },
        "gif": {
            "image/gif",
        },
        "webp": {
            "image/webp",
        },
        "pdf": {
            "application/pdf",
        },
        "txt": {
            "text/plain",
        },
        "json": {
            "application/json",
        },
    }

    UNSAFE_FILENAME_PATTERN = re.compile(
        r"(?:\.\./|\.\.\\\\|/|\\\\|\x00)"
    )

    def analyze(
        self,
        filename: str,
        mime_type: str | None = None,
        content_type: str | None = None,
    ) -> FileUploadAnalysis:
        if not isinstance(filename, str):
            raise TypeError("filename must be a string")

        if not filename.strip():
            raise ValueError("filename must not be empty")

        if mime_type is not None and not isinstance(
            mime_type,
            str,
        ):
            raise TypeError("mime_type must be a string or None")

        if content_type is not None and not isinstance(
            content_type,
            str,
        ):
            raise TypeError(
                "content_type must be a string or None"
            )

        indicators: list[FileUploadIndicator] = []

        normalized_filename = filename.strip()
        lower_filename = normalized_filename.lower()

        extension = self._extension(lower_filename)
        extensions = self._extensions(lower_filename)

        if extension in self.DANGEROUS_EXTENSIONS:
            indicators.append(
                FileUploadIndicator(
                    type=FileUploadIndicatorType.DANGEROUS_EXTENSION,
                    evidence=f"dangerous extension: .{extension}",
                    position=lower_filename.rfind(
                        f".{extension}"
                    ),
                )
            )

        if len(extensions) >= 2:
            dangerous_extensions = [
                item
                for item in extensions
                if item in self.DANGEROUS_EXTENSIONS
            ]

            if dangerous_extensions:
                indicators.append(
                    FileUploadIndicator(
                        type=FileUploadIndicatorType.DOUBLE_EXTENSION,
                        evidence=(
                            "multiple extensions with dangerous "
                            f"extension: {', '.join(dangerous_extensions)}"
                        ),
                        position=0,
                    )
                )

        if (
            self.UNSAFE_FILENAME_PATTERN.search(
                normalized_filename
            )
            or "/" in normalized_filename
            or "\\" in normalized_filename
        ):
            indicators.append(
                FileUploadIndicator(
                    type=FileUploadIndicatorType.UNSAFE_FILENAME,
                    evidence=(
                        f"unsafe filename pattern: {normalized_filename}"
                    ),
                    position=0,
                )
            )

        normalized_mime = self._normalize_mime(mime_type)
        normalized_content_type = self._normalize_mime(
            content_type
        )

        if normalized_mime in self.DANGEROUS_MIME_TYPES:
            indicators.append(
                FileUploadIndicator(
                    type=FileUploadIndicatorType.DANGEROUS_MIME,
                    evidence=(
                        f"dangerous MIME type: {normalized_mime}"
                    ),
                    position=0,
                )
            )

        if (
            normalized_content_type
            in self.EXECUTABLE_CONTENT_TYPES
        ):
            indicators.append(
                FileUploadIndicator(
                    type=(
                        FileUploadIndicatorType
                        .EXECUTABLE_CONTENT_TYPE
                    ),
                    evidence=(
                        "executable upload Content-Type: "
                        f"{normalized_content_type}"
                    ),
                    position=0,
                )
            )

        expected_mimes = self.SAFE_EXTENSION_MIME.get(
            extension
        )

        if (
            expected_mimes
            and normalized_mime
            and normalized_mime not in expected_mimes
        ):
            indicators.append(
                FileUploadIndicator(
                    type=FileUploadIndicatorType.MIME_MISMATCH,
                    evidence=(
                        f"extension .{extension} does not match "
                        f"MIME type {normalized_mime}"
                    ),
                    position=0,
                )
            )

        return FileUploadAnalysis(
            indicators=indicators
        )

    @staticmethod
    def _normalize_mime(
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return value.split(";", 1)[0].strip().lower()

    @staticmethod
    def _extensions(filename: str) -> list[str]:
        name = filename.replace("\\", "/")
        parts = name.split("/")

        if len(parts) > 1:
            name = parts[-1]

        parts = name.split(".")

        if len(parts) <= 1:
            return []

        return [
            part
            for part in parts[1:]
            if part
        ]

    @classmethod
    def _extension(cls, filename: str) -> str | None:
        extensions = cls._extensions(filename)
        if not extensions:
            return None

        return extensions[-1]
