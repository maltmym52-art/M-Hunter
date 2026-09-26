from dataclasses import dataclass
from enum import Enum


class PrototypePollutionIndicatorType(str, Enum):
    PROTO_KEY = "proto_key"
    CONSTRUCTOR_KEY = "constructor_key"
    PROTOTYPE_KEY = "prototype_key"
    NESTED_OBJECT = "nested_object"
    POLLUTION_MARKER = "pollution_marker"
    JAVASCRIPT_CONTEXT = "javascript_context"
    JSON_OBJECT = "json_object"
    QUERY_PARAMETER = "query_parameter"
    REQUEST_BODY = "request_body"


@dataclass(frozen=True)
class PrototypePollutionIndicator:
    type: PrototypePollutionIndicatorType
    evidence: str
    name: str
    value: str


@dataclass
class PrototypePollutionAnalysis:
    detected: bool
    count: int
    types: list[PrototypePollutionIndicatorType]
    names: list[str]
    indicators: list[PrototypePollutionIndicator]

    def has_type(self, indicator_type: PrototypePollutionIndicatorType) -> bool:
        return indicator_type in self.types


class PrototypePollutionAnalyzer:
    name = "prototype_pollution"
    description = "Detects indicators associated with JavaScript prototype pollution."

    _SUSPICIOUS_KEYS = {
        "__proto__",
        "constructor",
        "prototype",
    }

    _POLLUTION_MARKERS = {
        "polluted",
        "isadmin",
        "admin",
        "role",
        "status",
        "value",
    }

    _JAVASCRIPT_CONTENT_TYPES = {
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
    }

    def analyze(
        self,
        url: str,
        *,
        query: dict[str, str] | None = None,
        body: object | None = None,
        content_type: str | None = None,
        response_text: str = "",
    ) -> PrototypePollutionAnalysis:
        indicators: list[PrototypePollutionIndicator] = []

        self._inspect_mapping(
            query or {},
            indicators,
            PrototypePollutionIndicatorType.QUERY_PARAMETER,
        )

        if isinstance(body, dict):
            self._inspect_mapping(
                body,
                indicators,
                PrototypePollutionIndicatorType.REQUEST_BODY,
            )

        lowered_url = url.lower()
        if any(key in lowered_url for key in self._SUSPICIOUS_KEYS):
            indicators.append(
                PrototypePollutionIndicator(
                    type=PrototypePollutionIndicatorType.PROTO_KEY,
                    evidence="Suspicious prototype-related key detected in URL.",
                    name="url",
                    value=url,
                )
            )

        if content_type:
            normalized_type = content_type.split(";", 1)[0].strip().lower()
            if normalized_type in self._JAVASCRIPT_CONTENT_TYPES:
                indicators.append(
                    PrototypePollutionIndicator(
                        type=PrototypePollutionIndicatorType.JAVASCRIPT_CONTEXT,
                        evidence="JavaScript response context detected.",
                        name="content-type",
                        value=normalized_type,
                    )
                )

        lowered_response = response_text.lower()
        for marker in self._POLLUTION_MARKERS:
            if marker in lowered_response:
                indicators.append(
                    PrototypePollutionIndicator(
                        type=PrototypePollutionIndicatorType.POLLUTION_MARKER,
                        evidence=f"Potential pollution-related marker detected: {marker}.",
                        name="response",
                        value=marker,
                    )
                )

        if isinstance(body, dict):
            indicators.append(
                PrototypePollutionIndicator(
                    type=PrototypePollutionIndicatorType.JSON_OBJECT,
                    evidence="JSON-like object supplied as request data.",
                    name="body",
                    value="object",
                )
            )

        types = list(dict.fromkeys(item.type for item in indicators))
        names = list(dict.fromkeys(item.name for item in indicators))

        return PrototypePollutionAnalysis(
            detected=bool(indicators),
            count=len(indicators),
            types=types,
            names=names,
            indicators=indicators,
        )

    def _inspect_mapping(
        self,
        mapping: dict,
        indicators: list[PrototypePollutionIndicator],
        source_type: PrototypePollutionIndicatorType,
    ) -> None:
        for name, value in mapping.items():
            normalized_name = str(name).lower()
            normalized_value = str(value)

            if normalized_name == "__proto__":
                indicator_type = PrototypePollutionIndicatorType.PROTO_KEY
            elif normalized_name == "constructor":
                indicator_type = PrototypePollutionIndicatorType.CONSTRUCTOR_KEY
            elif normalized_name == "prototype":
                indicator_type = PrototypePollutionIndicatorType.PROTOTYPE_KEY
            elif isinstance(value, dict):
                indicator_type = PrototypePollutionIndicatorType.NESTED_OBJECT
            else:
                continue

            indicators.append(
                PrototypePollutionIndicator(
                    type=indicator_type,
                    evidence=f"Suspicious prototype-related input detected in {source_type.value}.",
                    name=str(name),
                    value=normalized_value,
                )
            )
