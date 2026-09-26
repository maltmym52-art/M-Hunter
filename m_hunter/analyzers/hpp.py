from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qs, urlparse


class HPPIndicatorType(str, Enum):
    DUPLICATE_PARAMETER = "duplicate_parameter"
    DUPLICATE_QUERY_PARAMETER = "duplicate_query_parameter"
    DUPLICATE_BODY_PARAMETER = "duplicate_body_parameter"
    PARAMETER_ARRAY = "parameter_array"
    CONFLICTING_VALUES = "conflicting_values"
    SAME_PARAMETER_DIFFERENT_VALUES = "same_parameter_different_values"


@dataclass(frozen=True)
class HPPIndicator:
    type: HPPIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass
class HPPAnalysis:
    indicators: list[HPPIndicator]

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> list[HPPIndicatorType]:
        return list(dict.fromkeys(i.type for i in self.indicators))

    @property
    def names(self) -> list[str]:
        return list(
            dict.fromkeys(
                i.name for i in self.indicators if i.name is not None
            )
        )

    def has_type(self, indicator_type: HPPIndicatorType) -> bool:
        return any(i.type == indicator_type for i in self.indicators)


class HPPAnalyzer:
    def analyze(
        self,
        *,
        url: str | None = None,
        params: dict[str, str | list[str]] | None = None,
        body: str | bytes | None = None,
        method: str | None = None,
    ) -> HPPAnalysis:
        if url is not None and not isinstance(url, str):
            raise TypeError("url must be a string or None")

        if params is not None and not isinstance(params, dict):
            raise TypeError("params must be a dictionary or None")

        if body is not None and not isinstance(body, (str, bytes)):
            raise TypeError("body must be str, bytes, or None")

        if method is not None and not isinstance(method, str):
            raise TypeError("method must be a string or None")

        indicators: list[HPPIndicator] = []

        query_pairs: list[tuple[str, str]] = []

        if url:
            parsed = urlparse(url)
            query_pairs = [
                (name, value)
                for name, values in parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                ).items()
                for value in values
            ]

            raw_query_pairs = [
                pair.split("=", 1)
                for pair in parsed.query.split("&")
                if pair
            ]

            raw_names = [pair[0] for pair in raw_query_pairs]

            for name in dict.fromkeys(raw_names):
                count = raw_names.count(name)

                if count > 1:
                    values = [
                        pair[1] if len(pair) > 1 else ""
                        for pair in raw_query_pairs
                        if pair[0] == name
                    ]

                    indicators.append(
                        HPPIndicator(
                            HPPIndicatorType.DUPLICATE_QUERY_PARAMETER,
                            f"Query parameter '{name}' appears {count} times.",
                            name=name,
                            value=",".join(values),
                        )
                    )

                    if len(set(values)) > 1:
                        indicators.append(
                            HPPIndicator(
                                HPPIndicatorType.CONFLICTING_VALUES,
                                (
                                    f"Parameter '{name}' has conflicting "
                                    f"values: {values}"
                                ),
                                name=name,
                                value=",".join(values),
                            )
                        )

        if params:
            for name, value in params.items():
                values = value if isinstance(value, list) else [value]

                if len(values) > 1:
                    indicators.append(
                        HPPIndicator(
                            HPPIndicatorType.DUPLICATE_PARAMETER,
                            (
                                f"Parameter '{name}' contains "
                                f"{len(values)} values."
                            ),
                            name=name,
                            value=",".join(str(v) for v in values),
                        )
                    )

                    indicators.append(
                        HPPIndicator(
                            HPPIndicatorType.PARAMETER_ARRAY,
                            f"Parameter '{name}' is represented as an array.",
                            name=name,
                            value=",".join(str(v) for v in values),
                        )
                    )

                    if len(set(str(v) for v in values)) > 1:
                        indicators.append(
                            HPPIndicator(
                                HPPIndicatorType.SAME_PARAMETER_DIFFERENT_VALUES,
                                (
                                    f"Parameter '{name}' contains different "
                                    f"values: {values}"
                                ),
                                name=name,
                                value=",".join(str(v) for v in values),
                            )
                        )

        if body:
            body_text = (
                body.decode("utf-8", errors="replace")
                if isinstance(body, bytes)
                else body
            )

            body_pairs = [
                pair.split("=", 1)
                for pair in body_text.split("&")
                if pair
            ]

            body_names = [pair[0] for pair in body_pairs]

            for name in dict.fromkeys(body_names):
                count = body_names.count(name)

                if count > 1:
                    values = [
                        pair[1] if len(pair) > 1 else ""
                        for pair in body_pairs
                        if pair[0] == name
                    ]

                    indicators.append(
                        HPPIndicator(
                            HPPIndicatorType.DUPLICATE_BODY_PARAMETER,
                            f"Body parameter '{name}' appears {count} times.",
                            name=name,
                            value=",".join(values),
                        )
                    )

                    if len(set(values)) > 1:
                        indicators.append(
                            HPPIndicator(
                                HPPIndicatorType.CONFLICTING_VALUES,
                                (
                                    f"Body parameter '{name}' has conflicting "
                                    f"values: {values}"
                                ),
                                name=name,
                                value=",".join(values),
                            )
                        )

        return HPPAnalysis(
            indicators=indicators,
        )
