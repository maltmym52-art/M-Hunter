from dataclasses import dataclass, field
from enum import Enum


class DeserializationIndicatorType(str, Enum):
    SERIALIZED_CONTENT_TYPE = "serialized_content_type"
    SERIALIZED_COOKIE = "serialized_cookie"
    SERIALIZED_PARAMETER = "serialized_parameter"
    SERIALIZED_FILE = "serialized_file"
    SERIALIZATION_HEADER = "serialization_header"


@dataclass(frozen=True)
class DeserializationIndicator:
    type: DeserializationIndicatorType
    evidence: str
    name: str | None = None


@dataclass
class DeserializationAnalysis:
    detected: bool = False
    indicator_count: int = 0
    types: list[DeserializationIndicatorType] = field(
        default_factory=list
    )
    names: list[str] = field(default_factory=list)
    indicators: list[DeserializationIndicator] = field(
        default_factory=list
    )

    @property
    def serialized_content_type_detected(self) -> bool:
        return (
            DeserializationIndicatorType.SERIALIZED_CONTENT_TYPE
            in self.types
        )

    @property
    def serialized_cookie_detected(self) -> bool:
        return (
            DeserializationIndicatorType.SERIALIZED_COOKIE
            in self.types
        )

    @property
    def serialized_parameter_detected(self) -> bool:
        return (
            DeserializationIndicatorType.SERIALIZED_PARAMETER
            in self.types
        )

    @property
    def serialized_file_detected(self) -> bool:
        return (
            DeserializationIndicatorType.SERIALIZED_FILE
            in self.types
        )

    @property
    def serialization_header_detected(self) -> bool:
        return (
            DeserializationIndicatorType.SERIALIZATION_HEADER
            in self.types
        )


class DeserializationAnalyzer:
    SERIALIZED_CONTENT_TYPES = {
        "application/x-java-serialized-object",
        "application/x-python-serialized",
        "application/x-ruby-marshal",
        "application/vnd.php.serialized",
    }

    SERIALIZATION_HEADERS = {
        "x-java-serialized-object",
        "x-serialized-object",
        "x-python-pickle",
        "x-ruby-marshal",
        "x-php-serialized",
    }

    SERIALIZED_PARAMETER_NAMES = {
        "serialized",
        "serialize",
        "serialized_data",
        "serializeddata",
        "object",
        "object_data",
        "objectdata",
        "pickle",
        "marshal",
        "java_object",
        "javaobject",
    }

    SERIALIZED_COOKIE_NAMES = {
        "serialized",
        "serialized_data",
        "serializeddata",
        "object",
        "object_data",
        "objectdata",
        "pickle",
        "marshal",
        "java_object",
        "javaobject",
    }

    SERIALIZED_FILE_EXTENSIONS = {
        ".ser",
        ".serialized",
        ".pickle",
        ".pkl",
        ".marshal",
        ".class",
    }

    def analyze(
        self,
        *,
        headers: dict[str, str] | None = None,
        parameters: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        filename: str | None = None,
    ) -> DeserializationAnalysis:
        for value in (
            headers,
            parameters,
            cookies,
        ):
            if value is not None and not isinstance(value, dict):
                raise TypeError(
                    "headers, parameters, and cookies must be dictionaries"
                )

        if filename is not None and not isinstance(filename, str):
            raise TypeError("filename must be a string or None")

        headers = headers or {}
        parameters = parameters or {}
        cookies = cookies or {}

        indicators: list[DeserializationIndicator] = []

        normalized_headers = {
            name.strip().lower(): value.strip().lower()
            for name, value in headers.items()
            if isinstance(name, str) and isinstance(value, str)
        }

        content_type = normalized_headers.get("content-type", "")
        if content_type.split(";", 1)[0].strip() in (
            self.SERIALIZED_CONTENT_TYPES
        ):
            indicators.append(
                DeserializationIndicator(
                    type=(
                        DeserializationIndicatorType
                        .SERIALIZED_CONTENT_TYPE
                    ),
                    evidence=(
                        f"Serialized content type detected: "
                        f"{content_type}"
                    ),
                    name="content-type",
                )
            )

        for header_name in normalized_headers:
            if header_name in self.SERIALIZATION_HEADERS:
                indicators.append(
                    DeserializationIndicator(
                        type=(
                            DeserializationIndicatorType
                            .SERIALIZATION_HEADER
                        ),
                        evidence=(
                            f"Serialization-related header detected: "
                            f"{header_name}"
                        ),
                        name=header_name,
                    )
                )

        for name in parameters:
            if (
                isinstance(name, str)
                and name.strip().lower()
                in self.SERIALIZED_PARAMETER_NAMES
            ):
                normalized = name.strip().lower()
                indicators.append(
                    DeserializationIndicator(
                        type=(
                            DeserializationIndicatorType
                            .SERIALIZED_PARAMETER
                        ),
                        evidence=(
                            f"Serialization-related parameter detected: "
                            f"{name}"
                        ),
                        name=normalized,
                    )
                )

        for name in cookies:
            if (
                isinstance(name, str)
                and name.strip().lower()
                in self.SERIALIZED_COOKIE_NAMES
            ):
                normalized = name.strip().lower()
                indicators.append(
                    DeserializationIndicator(
                        type=(
                            DeserializationIndicatorType
                            .SERIALIZED_COOKIE
                        ),
                        evidence=(
                            f"Serialization-related cookie detected: "
                            f"{name}"
                        ),
                        name=normalized,
                    )
                )

        if filename:
            lower_filename = filename.strip().lower()
            if any(
                lower_filename.endswith(extension)
                for extension in self.SERIALIZED_FILE_EXTENSIONS
            ):
                indicators.append(
                    DeserializationIndicator(
                        type=(
                            DeserializationIndicatorType
                            .SERIALIZED_FILE
                        ),
                        evidence=(
                            f"Serialized file extension detected: "
                            f"{filename}"
                        ),
                        name=filename,
                    )
                )

        types: list[DeserializationIndicatorType] = []
        names: list[str] = []

        for indicator in indicators:
            if indicator.type not in types:
                types.append(indicator.type)

            if indicator.name and indicator.name not in names:
                names.append(indicator.name)

        return DeserializationAnalysis(
            detected=bool(indicators),
            indicator_count=len(indicators),
            types=types,
            names=names,
            indicators=indicators,
        )
