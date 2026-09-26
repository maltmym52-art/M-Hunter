from dataclasses import dataclass
from enum import Enum


class NoSQLInjectionIndicatorType(str, Enum):
    MONGODB_OPERATOR = "mongodb_operator"
    QUERY_OPERATOR = "query_operator"
    JSON_OPERATOR = "json_operator"
    REGEX_OPERATOR = "regex_operator"
    JAVASCRIPT_OPERATOR = "javascript_operator"
    DOLLAR_PREFIX = "dollar_prefix"
    DOT_NOTATION = "dot_notation"
    QUERY_OBJECT = "query_object"
    DATABASE_ERROR = "database_error"
    MONGODB_CONTEXT = "mongodb_context"


@dataclass(frozen=True)
class NoSQLInjectionIndicator:
    type: NoSQLInjectionIndicatorType
    evidence: str
    name: str
    value: str


@dataclass
class NoSQLInjectionAnalysis:
    detected: bool
    count: int
    types: list[NoSQLInjectionIndicatorType]
    names: list[str]
    indicators: list[NoSQLInjectionIndicator]

    def has_type(self, indicator_type: NoSQLInjectionIndicatorType) -> bool:
        return indicator_type in self.types


class NoSQLInjectionAnalyzer:
    name = "nosql_injection"
    description = "Detects indicators associated with NoSQL injection."

    _MONGODB_OPERATORS = {
        "$eq",
        "$ne",
        "$gt",
        "$gte",
        "$lt",
        "$lte",
        "$in",
        "$nin",
        "$exists",
        "$regex",
        "$where",
        "$expr",
        "$or",
        "$and",
        "$nor",
        "$not",
        "$elemMatch",
        "$all",
        "$size",
        "$type",
        "$text",
    }

    _REGEX_OPERATORS = {
        "$regex",
        "$options",
    }

    _JAVASCRIPT_OPERATORS = {
        "$where",
        "$function",
        "$accumulator",
    }

    _DATABASE_ERROR_MARKERS = {
        "mongodb",
        "mongoerror",
        "mongoservererror",
        "bson",
        "cast to objectid failed",
        "unknown operator",
        "badvalue",
        "queryplanner",
    }

    def analyze(
        self,
        url: str,
        *,
        query: dict[str, object] | None = None,
        body: object | None = None,
        content_type: str | None = None,
        response_text: str = "",
    ) -> NoSQLInjectionAnalysis:
        indicators: list[NoSQLInjectionIndicator] = []

        self._inspect_mapping(
            query or {},
            indicators,
            source="query",
        )

        if isinstance(body, dict):
            self._inspect_mapping(
                body,
                indicators,
                source="body",
            )

        lowered_url = url.lower()

        if any(
            operator in lowered_url
            for operator in self._MONGODB_OPERATORS
        ):
            indicators.append(
                NoSQLInjectionIndicator(
                    type=NoSQLInjectionIndicatorType.MONGODB_OPERATOR,
                    evidence=(
                        "MongoDB/NoSQL query operator detected in URL."
                    ),
                    name="url",
                    value=url,
                )
            )

        if "." in url:
            for segment in url.split("?")[0].split("/"):
                if "." in segment and segment.startswith("$"):
                    indicators.append(
                        NoSQLInjectionIndicator(
                            type=NoSQLInjectionIndicatorType.DOT_NOTATION,
                            evidence=(
                                "Dot notation associated with NoSQL "
                                "object traversal detected."
                            ),
                            name="url",
                            value=segment,
                        )
                    )

        if content_type:
            normalized_type = (
                content_type.split(";", 1)[0].strip().lower()
            )

            if normalized_type in {
                "application/json",
                "application/problem+json",
            }:
                indicators.append(
                    NoSQLInjectionIndicator(
                        type=NoSQLInjectionIndicatorType.JSON_OPERATOR,
                        evidence="JSON request/response context detected.",
                        name="content-type",
                        value=normalized_type,
                    )
                )

        lowered_response = response_text.lower()

        for marker in self._DATABASE_ERROR_MARKERS:
            if marker in lowered_response:
                indicators.append(
                    NoSQLInjectionIndicator(
                        type=NoSQLInjectionIndicatorType.DATABASE_ERROR,
                        evidence=(
                            f"Potential NoSQL database error marker "
                            f"detected: {marker}."
                        ),
                        name="response",
                        value=marker,
                    )
                )

        if "mongodb" in lowered_response or "mongoose" in lowered_response:
            indicators.append(
                NoSQLInjectionIndicator(
                    type=NoSQLInjectionIndicatorType.MONGODB_CONTEXT,
                    evidence="MongoDB-related response context detected.",
                    name="response",
                    value="mongodb",
                )
            )

        types = list(dict.fromkeys(
            indicator.type for indicator in indicators
        ))
        names = list(dict.fromkeys(
            indicator.name for indicator in indicators
        ))

        return NoSQLInjectionAnalysis(
            detected=bool(indicators),
            count=len(indicators),
            types=types,
            names=names,
            indicators=indicators,
        )

    def _inspect_mapping(
        self,
        mapping: dict,
        indicators: list[NoSQLInjectionIndicator],
        *,
        source: str,
    ) -> None:
        for name, value in mapping.items():
            normalized_name = str(name).lower()
            normalized_value = str(value)

            if normalized_name in self._REGEX_OPERATORS:
                indicator_type = NoSQLInjectionIndicatorType.REGEX_OPERATOR
            elif normalized_name in self._JAVASCRIPT_OPERATORS:
                indicator_type = (
                    NoSQLInjectionIndicatorType.JAVASCRIPT_OPERATOR
                )
            elif normalized_name in self._MONGODB_OPERATORS:
                indicator_type = (
                    NoSQLInjectionIndicatorType.MONGODB_OPERATOR
                )
            elif normalized_name.startswith("$"):
                indicator_type = NoSQLInjectionIndicatorType.DOLLAR_PREFIX
            elif "." in normalized_name:
                indicator_type = NoSQLInjectionIndicatorType.DOT_NOTATION
            elif isinstance(value, dict):
                indicator_type = NoSQLInjectionIndicatorType.QUERY_OBJECT
            else:
                continue

            indicators.append(
                NoSQLInjectionIndicator(
                    type=indicator_type,
                    evidence=(
                        f"NoSQL-related input detected in {source}."
                    ),
                    name=str(name),
                    value=normalized_value,
                )
            )
