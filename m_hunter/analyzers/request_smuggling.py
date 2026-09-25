from dataclasses import dataclass, field
from enum import Enum


class SmugglingType(str, Enum):
    CL_TE = "cl_te"
    TE_CL = "te_cl"
    TE_TE = "te_te"
    DUPLICATE_CONTENT_LENGTH = "duplicate_content_length"
    INVALID_TRANSFER_ENCODING = "invalid_transfer_encoding"


class SmugglingIndicatorType(str, Enum):
    CONFLICTING_FRAMING = "conflicting_framing"
    DUPLICATE_CONTENT_LENGTH = "duplicate_content_length"
    AMBIGUOUS_TRANSFER_ENCODING = "ambiguous_transfer_encoding"


@dataclass(frozen=True)
class SmugglingIndicator:
    type: SmugglingIndicatorType
    evidence: str
    position: int | None = None
    smuggling_type: SmugglingType | None = None


@dataclass
class RequestSmugglingAnalysis:
    detected: bool = False
    indicator_count: int = 0
    smuggling_types: list[SmugglingType] = field(default_factory=list)
    types: list[SmugglingIndicatorType] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    indicators: list[SmugglingIndicator] = field(default_factory=list)

    @property
    def conflicting_framing_detected(self) -> bool:
        return (
            SmugglingIndicatorType.CONFLICTING_FRAMING
            in self.types
        )

    @property
    def duplicate_content_length_detected(self) -> bool:
        return (
            SmugglingIndicatorType.DUPLICATE_CONTENT_LENGTH
            in self.types
        )

    @property
    def ambiguous_transfer_encoding_detected(self) -> bool:
        return (
            SmugglingIndicatorType.AMBIGUOUS_TRANSFER_ENCODING
            in self.types
        )


class RequestSmugglingAnalyzer:
    def analyze(
        self,
        headers: dict[str, str | list[str]],
    ) -> RequestSmugglingAnalysis:
        if not isinstance(headers, dict):
            raise TypeError("headers must be a dict")

        normalized: dict[str, list[str]] = {}

        for name, value in headers.items():
            if not isinstance(name, str):
                raise TypeError("header names must be strings")

            key = name.strip().lower()

            if not key:
                raise ValueError("header names must not be empty")

            if isinstance(value, str):
                values = [value]
            elif isinstance(value, list):
                values = value
            else:
                raise TypeError(
                    "header values must be strings or lists of strings"
                )

            if not all(isinstance(item, str) for item in values):
                raise TypeError(
                    "header values must be strings or lists of strings"
                )

            normalized.setdefault(key, []).extend(values)

        indicators: list[SmugglingIndicator] = []
        smuggling_types: list[SmugglingType] = []

        content_lengths = normalized.get("content-length", [])
        transfer_encoding = normalized.get(
            "transfer-encoding",
            [],
        )

        transfer_tokens = [
            token.strip().lower()
            for value in transfer_encoding
            for token in value.split(",")
            if token.strip()
        ]

        has_content_length = bool(content_lengths)
        has_transfer_encoding = bool(transfer_tokens)

        if has_content_length and has_transfer_encoding:
            if "chunked" in transfer_tokens:
                smuggling_type = SmugglingType.CL_TE
            else:
                smuggling_type = SmugglingType.TE_CL

            indicators.append(
                SmugglingIndicator(
                    type=SmugglingIndicatorType.CONFLICTING_FRAMING,
                    evidence=(
                        "Content-Length and Transfer-Encoding are "
                        "present in the same request."
                    ),
                    smuggling_type=smuggling_type,
                )
            )
            smuggling_types.append(smuggling_type)

        if len(content_lengths) > 1:
            indicators.append(
                SmugglingIndicator(
                    type=SmugglingIndicatorType.DUPLICATE_CONTENT_LENGTH,
                    evidence=(
                        f"Multiple Content-Length values detected: "
                        f"{content_lengths}"
                    ),
                    smuggling_type=SmugglingType.DUPLICATE_CONTENT_LENGTH,
                )
            )
            smuggling_types.append(
                SmugglingType.DUPLICATE_CONTENT_LENGTH
            )

        if len(transfer_tokens) > 1:
            unique_tokens = list(dict.fromkeys(transfer_tokens))

            if len(unique_tokens) > 1:
                indicators.append(
                    SmugglingIndicator(
                        type=(
                            SmugglingIndicatorType
                            .AMBIGUOUS_TRANSFER_ENCODING
                        ),
                        evidence=(
                            "Multiple Transfer-Encoding tokens detected: "
                            f"{transfer_tokens}"
                        ),
                        smuggling_type=SmugglingType.TE_TE,
                    )
                )
                smuggling_types.append(SmugglingType.TE_TE)

        if transfer_tokens and any(
            token != "chunked" for token in transfer_tokens
        ):
            indicators.append(
                SmugglingIndicator(
                    type=(
                        SmugglingIndicatorType
                        .AMBIGUOUS_TRANSFER_ENCODING
                    ),
                    evidence=(
                        "Transfer-Encoding contains a token other "
                        f"than chunked: {transfer_tokens}"
                    ),
                    smuggling_type=SmugglingType.INVALID_TRANSFER_ENCODING,
                )
            )
            smuggling_types.append(
                SmugglingType.INVALID_TRANSFER_ENCODING
            )

        types: list[SmugglingIndicatorType] = []
        names: list[str] = []

        for indicator in indicators:
            if indicator.type not in types:
                types.append(indicator.type)

            if indicator.type.value not in names:
                names.append(indicator.type.value)

        unique_smuggling_types = list(
            dict.fromkeys(smuggling_types)
        )

        return RequestSmugglingAnalysis(
            detected=bool(indicators),
            indicator_count=len(indicators),
            smuggling_types=unique_smuggling_types,
            types=types,
            names=names,
            indicators=indicators,
        )
