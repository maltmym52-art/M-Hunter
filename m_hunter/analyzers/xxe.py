from dataclasses import dataclass, field
from enum import Enum
import re


class XXEIndicatorType(str, Enum):
    DOCTYPE_DECLARATION = "doctype_declaration"
    ENTITY_DECLARATION = "entity_declaration"
    EXTERNAL_ENTITY = "external_entity"
    SYSTEM_IDENTIFIER = "system_identifier"
    PUBLIC_IDENTIFIER = "public_identifier"
    ENTITY_REFERENCE = "entity_reference"


@dataclass(frozen=True)
class XXEIndicator:
    type: XXEIndicatorType
    evidence: str
    position: int | None = None


@dataclass
class XXEAnalysis:
    detected: bool = False
    indicator_count: int = 0
    types: list[XXEIndicatorType] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    indicators: list[XXEIndicator] = field(default_factory=list)

    @property
    def doctype_detected(self) -> bool:
        return XXEIndicatorType.DOCTYPE_DECLARATION in self.types

    @property
    def entity_declaration_detected(self) -> bool:
        return XXEIndicatorType.ENTITY_DECLARATION in self.types

    @property
    def external_entity_detected(self) -> bool:
        return XXEIndicatorType.EXTERNAL_ENTITY in self.types

    @property
    def external_identifier_detected(self) -> bool:
        return (
            XXEIndicatorType.SYSTEM_IDENTIFIER in self.types
            or XXEIndicatorType.PUBLIC_IDENTIFIER in self.types
        )


class XXEAnalyzer:
    DOCTYPE_PATTERN = re.compile(
        r"<!DOCTYPE\b[^>]{0,500}>",
        re.IGNORECASE | re.DOTALL,
    )

    ENTITY_PATTERN = re.compile(
        r"<!ENTITY\b[^>]{0,500}>",
        re.IGNORECASE | re.DOTALL,
    )

    EXTERNAL_ENTITY_PATTERN = re.compile(
        r"<!ENTITY\b[^>]{0,500}\b(?:SYSTEM|PUBLIC)\b[^>]{0,500}>",
        re.IGNORECASE | re.DOTALL,
    )

    SYSTEM_PATTERN = re.compile(
        r"\bSYSTEM\s+[\"'][^\"']{1,500}[\"']",
        re.IGNORECASE,
    )

    PUBLIC_PATTERN = re.compile(
        r"\bPUBLIC\s+[\"'][^\"']{1,500}[\"']",
        re.IGNORECASE,
    )

    ENTITY_REFERENCE_PATTERN = re.compile(
        r"&[A-Za-z_:][A-Za-z0-9_.:-]*;",
    )

    def analyze(self, content: str | bytes) -> XXEAnalysis:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        if not isinstance(content, str):
            raise TypeError("content must be str or bytes")

        indicators: list[XXEIndicator] = []

        for match in self.DOCTYPE_PATTERN.finditer(content):
            indicators.append(
                XXEIndicator(
                    type=XXEIndicatorType.DOCTYPE_DECLARATION,
                    evidence=match.group(0),
                    position=match.start(),
                )
            )

        for match in self.ENTITY_PATTERN.finditer(content):
            indicators.append(
                XXEIndicator(
                    type=XXEIndicatorType.ENTITY_DECLARATION,
                    evidence=match.group(0),
                    position=match.start(),
                )
            )

        for match in self.EXTERNAL_ENTITY_PATTERN.finditer(content):
            indicators.append(
                XXEIndicator(
                    type=XXEIndicatorType.EXTERNAL_ENTITY,
                    evidence=match.group(0),
                    position=match.start(),
                )
            )

        for match in self.SYSTEM_PATTERN.finditer(content):
            indicators.append(
                XXEIndicator(
                    type=XXEIndicatorType.SYSTEM_IDENTIFIER,
                    evidence=match.group(0),
                    position=match.start(),
                )
            )

        for match in self.PUBLIC_PATTERN.finditer(content):
            indicators.append(
                XXEIndicator(
                    type=XXEIndicatorType.PUBLIC_IDENTIFIER,
                    evidence=match.group(0),
                    position=match.start(),
                )
            )

        for match in self.ENTITY_REFERENCE_PATTERN.finditer(content):
            indicators.append(
                XXEIndicator(
                    type=XXEIndicatorType.ENTITY_REFERENCE,
                    evidence=match.group(0),
                    position=match.start(),
                )
            )

        types: list[XXEIndicatorType] = []
        names: list[str] = []

        for indicator in indicators:
            if indicator.type not in types:
                types.append(indicator.type)

            if indicator.type.value not in names:
                names.append(indicator.type.value)

        return XXEAnalysis(
            detected=bool(indicators),
            indicator_count=len(indicators),
            types=types,
            names=names,
            indicators=indicators,
        )
