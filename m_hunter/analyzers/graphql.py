from dataclasses import dataclass, field
from enum import Enum


class GraphQLIndicatorType(str, Enum):
    INTROSPECTION_ENABLED = "introspection_enabled"
    QUERY_OPERATION = "query_operation"
    MUTATION_OPERATION = "mutation_operation"
    SUBSCRIPTION_OPERATION = "subscription_operation"
    ALIAS_USAGE = "alias_usage"
    BATCHING = "batching"
    DEEP_QUERY = "deep_query"
    LARGE_QUERY = "large_query"
    SENSITIVE_FIELD = "sensitive_field"


@dataclass(frozen=True)
class GraphQLIndicator:
    type: GraphQLIndicatorType
    evidence: str
    name: str | None = None
    position: int | None = None


@dataclass
class GraphQLAnalysis:
    detected: bool = False
    indicator_count: int = 0
    types: list[GraphQLIndicatorType] = field(
        default_factory=list
    )
    names: list[str] = field(default_factory=list)
    indicators: list[GraphQLIndicator] = field(
        default_factory=list
    )

    @property
    def introspection_enabled(self) -> bool:
        return (
            GraphQLIndicatorType.INTROSPECTION_ENABLED
            in self.types
        )

    @property
    def query_detected(self) -> bool:
        return (
            GraphQLIndicatorType.QUERY_OPERATION
            in self.types
        )

    @property
    def mutation_detected(self) -> bool:
        return (
            GraphQLIndicatorType.MUTATION_OPERATION
            in self.types
        )

    @property
    def subscription_detected(self) -> bool:
        return (
            GraphQLIndicatorType.SUBSCRIPTION_OPERATION
            in self.types
        )

    @property
    def alias_detected(self) -> bool:
        return (
            GraphQLIndicatorType.ALIAS_USAGE
            in self.types
        )

    @property
    def batching_detected(self) -> bool:
        return (
            GraphQLIndicatorType.BATCHING
            in self.types
        )

    @property
    def deep_query_detected(self) -> bool:
        return (
            GraphQLIndicatorType.DEEP_QUERY
            in self.types
        )

    @property
    def large_query_detected(self) -> bool:
        return (
            GraphQLIndicatorType.LARGE_QUERY
            in self.types
        )

    @property
    def sensitive_field_detected(self) -> bool:
        return (
            GraphQLIndicatorType.SENSITIVE_FIELD
            in self.types
        )


class GraphQLAnalyzer:
    SENSITIVE_FIELDS = {
        "password",
        "passwordhash",
        "passwd",
        "secret",
        "token",
        "accesstoken",
        "refreshtoken",
        "authorization",
        "api_key",
        "apikey",
        "privatekey",
        "creditcard",
        "cardnumber",
        "ssn",
    }

    def analyze(
        self,
        query: str | None = None,
        *,
        introspection_enabled: bool = False,
        batch_count: int = 1,
        max_depth: int = 0,
        large_query_threshold: int = 5000,
    ) -> GraphQLAnalysis:
        if query is not None and not isinstance(query, str):
            raise TypeError("query must be a string or None")

        if not isinstance(introspection_enabled, bool):
            raise TypeError(
                "introspection_enabled must be a boolean"
            )

        if not isinstance(batch_count, int):
            raise TypeError("batch_count must be an integer")

        if not isinstance(max_depth, int):
            raise TypeError("max_depth must be an integer")

        if not isinstance(large_query_threshold, int):
            raise TypeError(
                "large_query_threshold must be an integer"
            )

        if batch_count < 1:
            raise ValueError("batch_count must be at least 1")

        if max_depth < 0:
            raise ValueError("max_depth must not be negative")

        if large_query_threshold < 1:
            raise ValueError(
                "large_query_threshold must be positive"
            )

        query = query or ""
        indicators: list[GraphQLIndicator] = []

        if introspection_enabled:
            indicators.append(
                GraphQLIndicator(
                    type=(
                        GraphQLIndicatorType
                        .INTROSPECTION_ENABLED
                    ),
                    evidence=(
                        "GraphQL introspection is enabled."
                    ),
                    name="introspection",
                )
            )

        normalized = query.lower()

        operation_patterns = (
            (
                GraphQLIndicatorType.QUERY_OPERATION,
                "query",
                "GraphQL query operation detected.",
            ),
            (
                GraphQLIndicatorType.MUTATION_OPERATION,
                "mutation",
                "GraphQL mutation operation detected.",
            ),
            (
                GraphQLIndicatorType.SUBSCRIPTION_OPERATION,
                "subscription",
                "GraphQL subscription operation detected.",
            ),
        )

        for indicator_type, keyword, evidence in operation_patterns:
            if keyword in normalized:
                indicators.append(
                    GraphQLIndicator(
                        type=indicator_type,
                        evidence=evidence,
                        name=keyword,
                    )
                )

        if "{" in query and ":" in query:
            indicators.append(
                GraphQLIndicator(
                    type=GraphQLIndicatorType.ALIAS_USAGE,
                    evidence=(
                        "GraphQL alias syntax may be present."
                    ),
                    name="alias",
                )
            )

        if batch_count > 1:
            indicators.append(
                GraphQLIndicator(
                    type=GraphQLIndicatorType.BATCHING,
                    evidence=(
                        f"GraphQL batch request detected: "
                        f"{batch_count} operations."
                    ),
                    name="batch",
                )
            )

        if max_depth > 5:
            indicators.append(
                GraphQLIndicator(
                    type=GraphQLIndicatorType.DEEP_QUERY,
                    evidence=(
                        f"GraphQL query depth is {max_depth}."
                    ),
                    name="depth",
                )
            )

        if len(query) >= large_query_threshold:
            indicators.append(
                GraphQLIndicator(
                    type=GraphQLIndicatorType.LARGE_QUERY,
                    evidence=(
                        f"GraphQL query length is {len(query)} "
                        f"bytes."
                    ),
                    name="query_length",
                )
            )

        for field in self.SENSITIVE_FIELDS:
            if field in normalized:
                indicators.append(
                    GraphQLIndicator(
                        type=(
                            GraphQLIndicatorType
                            .SENSITIVE_FIELD
                        ),
                        evidence=(
                            f"Potentially sensitive GraphQL "
                            f"field detected: {field}."
                        ),
                        name=field,
                    )
                )

        types: list[GraphQLIndicatorType] = []
        names: list[str] = []

        for indicator in indicators:
            if indicator.type not in types:
                types.append(indicator.type)

            if indicator.name and indicator.name not in names:
                names.append(indicator.name)

        return GraphQLAnalysis(
            detected=bool(indicators),
            indicator_count=len(indicators),
            types=types,
            names=names,
            indicators=indicators,
        )
