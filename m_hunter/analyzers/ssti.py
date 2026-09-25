from dataclasses import dataclass, field
from enum import Enum
import re


class SSTIEngine(str, Enum):
    JINJA2 = "jinja2"
    TWIG = "twig"
    DJANGO = "django"
    FREEMARKER = "freemarker"
    VELOCITY = "velocity"
    THYMELEAF = "thymeleaf"
    ERB = "erb"
    UNKNOWN = "unknown"


class SSTIIndicatorType(str, Enum):
    TEMPLATE_SYNTAX = "template_syntax"
    EXPRESSION_REFLECTION = "expression_reflection"
    ENGINE_MARKER = "engine_marker"


@dataclass(frozen=True)
class SSTIIndicator:
    type: SSTIIndicatorType
    evidence: str
    position: int | None = None
    engine: SSTIEngine = SSTIEngine.UNKNOWN


@dataclass
class SSTIAnalysis:
    detected: bool = False
    indicator_count: int = 0
    engines: list[SSTIEngine] = field(default_factory=list)
    types: list[SSTIIndicatorType] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    indicators: list[SSTIIndicator] = field(default_factory=list)

    @property
    def template_syntax_detected(self) -> bool:
        return SSTIIndicatorType.TEMPLATE_SYNTAX in self.types

    @property
    def expression_reflected(self) -> bool:
        return SSTIIndicatorType.EXPRESSION_REFLECTION in self.types

    @property
    def engine_marker_detected(self) -> bool:
        return SSTIIndicatorType.ENGINE_MARKER in self.types


class SSTIAnalyzer:
    """
    Passive Server-Side Template Injection indicator analyzer.

    This analyzer detects template-like syntax and engine markers in
    supplied response content. It does not execute template payloads
    and does not confirm server-side evaluation.
    """

    PATTERNS = (
        (
            SSTIEngine.JINJA2,
            re.compile(r"\{\{[^{}\n]{1,200}\}\}"),
        ),
        (
            SSTIEngine.TWIG,
            re.compile(r"\{\{[^{}\n]{1,200}\}\}"),
        ),
        (
            SSTIEngine.DJANGO,
            re.compile(r"\{\{[^{}\n]{1,200}\}\}"),
        ),
        (
            SSTIEngine.FREEMARKER,
            re.compile(r"\$\{[^{}\n]{1,200}\}"),
        ),
        (
            SSTIEngine.VELOCITY,
            re.compile(r"#(?:set|if|foreach|parse)\b", re.IGNORECASE),
        ),
        (
            SSTIEngine.THYMELEAF,
            re.compile(
                r"\bth:(?:text|utext|href|src|action|each|if|unless)\b",
                re.IGNORECASE,
            ),
        ),
        (
            SSTIEngine.ERB,
            re.compile(r"<%=?[^%\n]{0,200}%>"),
        ),
    )

    ENGINE_MARKERS = {
        SSTIEngine.JINJA2: (
            "jinja2",
            "jinja",
        ),
        SSTIEngine.TWIG: (
            "twig",
        ),
        SSTIEngine.DJANGO: (
            "django",
        ),
        SSTIEngine.FREEMARKER: (
            "freemarker",
        ),
        SSTIEngine.VELOCITY: (
            "velocity",
        ),
        SSTIEngine.THYMELEAF: (
            "thymeleaf",
        ),
        SSTIEngine.ERB: (
            "erb",
            "rails",
        ),
    }

    def analyze(
        self,
        content: str | bytes,
        *,
        marker: str | None = None,
    ) -> SSTIAnalysis:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        if not isinstance(content, str):
            raise TypeError("content must be str or bytes")

        indicators: list[SSTIIndicator] = []

        for engine, pattern in self.PATTERNS:
            for match in pattern.finditer(content):
                indicators.append(
                    SSTIIndicator(
                        type=SSTIIndicatorType.TEMPLATE_SYNTAX,
                        evidence=match.group(0),
                        position=match.start(),
                        engine=engine,
                    )
                )

        if marker:
            if not isinstance(marker, str):
                raise TypeError("marker must be a string")

            if marker:
                position = content.find(marker)

                if position >= 0:
                    indicators.append(
                        SSTIIndicator(
                            type=SSTIIndicatorType.EXPRESSION_REFLECTION,
                            evidence=marker,
                            position=position,
                            engine=SSTIEngine.UNKNOWN,
                        )
                    )

        lower_content = content.lower()

        for engine, markers in self.ENGINE_MARKERS.items():
            for engine_marker in markers:
                position = lower_content.find(engine_marker)

                if position >= 0:
                    indicators.append(
                        SSTIIndicator(
                            type=SSTIIndicatorType.ENGINE_MARKER,
                            evidence=engine_marker,
                            position=position,
                            engine=engine,
                        )
                    )

        engines: list[SSTIEngine] = []
        types: list[SSTIIndicatorType] = []
        names: list[str] = []

        for indicator in indicators:
            if (
                indicator.engine != SSTIEngine.UNKNOWN
                and indicator.engine not in engines
            ):
                engines.append(indicator.engine)

            if indicator.type not in types:
                types.append(indicator.type)

            if indicator.type.value not in names:
                names.append(indicator.type.value)

        return SSTIAnalysis(
            detected=bool(indicators),
            indicator_count=len(indicators),
            engines=engines,
            types=types,
            names=names,
            indicators=indicators,
        )
