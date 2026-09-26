from dataclasses import dataclass
from enum import Enum
from urllib.parse import unquote


class LDAPInjectionIndicatorType(str, Enum):
    LDAP_PARAMETER = "ldap_parameter"
    FILTER_PARAMETER = "filter_parameter"
    SEARCH_PARAMETER = "search_parameter"
    LDAP_MARKER = "ldap_marker"
    FILTER_SYNTAX = "filter_syntax"
    WILDCARD = "wildcard"
    GROUPING_OPERATOR = "grouping_operator"
    LOGICAL_OPERATOR = "logical_operator"
    ATTRIBUTE_OPERATOR = "attribute_operator"
    LDAP_ESCAPE_SEQUENCE = "ldap_escape_sequence"
    LDAP_ERROR = "ldap_error"
    LDAP_RESULT = "ldap_result"
    USER_CONTROLLED_FILTER = "user_controlled_filter"


@dataclass(frozen=True)
class LDAPInjectionIndicator:
    type: LDAPInjectionIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class LDAPInjectionAnalysis:
    indicators: tuple[LDAPInjectionIndicator, ...]

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> set[LDAPInjectionIndicatorType]:
        return {indicator.type for indicator in self.indicators}

    @property
    def names(self) -> set[str]:
        return {
            indicator.name
            for indicator in self.indicators
            if indicator.name is not None
        }

    def has_type(self, indicator_type: LDAPInjectionIndicatorType) -> bool:
        return indicator_type in self.types


class LDAPInjectionAnalyzer:
    LDAP_PARAMETERS = {
        "ldap": LDAPInjectionIndicatorType.LDAP_PARAMETER,
        "ldap_filter": LDAPInjectionIndicatorType.FILTER_PARAMETER,
        "filter": LDAPInjectionIndicatorType.FILTER_PARAMETER,
        "search": LDAPInjectionIndicatorType.SEARCH_PARAMETER,
        "search_filter": LDAPInjectionIndicatorType.SEARCH_PARAMETER,
        "query": LDAPInjectionIndicatorType.SEARCH_PARAMETER,
        "dn": LDAPInjectionIndicatorType.LDAP_PARAMETER,
        "uid": LDAPInjectionIndicatorType.LDAP_PARAMETER,
    }

    LDAP_MARKERS = (
        "ldap",
        "filter",
        "search",
        "distinguished_name",
        "dn",
    )

    LOGICAL_OPERATORS = ("&", "|", "!")
    GROUPING_OPERATORS = ("(", ")")
    ATTRIBUTE_OPERATORS = ("=", "~=", ">=", "<=")
    ESCAPE_SEQUENCES = ("\\2a", "\\28", "\\29", "\\5c", "\\00")

    ERROR_MARKERS = (
        "ldap error",
        "ldapexception",
        "ldap exception",
        "invalid ldap",
        "invalid filter",
        "bad search filter",
        "filter error",
        "protocol error",
        "operations error",
        "search filter",
    )

    RESULT_MARKERS = (
        "distinguishedname",
        "distinguished name",
        "objectclass",
        "objectcategory",
        "ldap result",
        "search result",
    )

    def analyze(
        self,
        *,
        url: str | None = None,
        params: dict[str, str] | None = None,
        body: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        response_body: str | bytes | None = None,
        parameter_names: list[str] | tuple[str, ...] | None = None,
        ldap_query: str | None = None,
        user_controlled_filter: bool | None = None,
    ) -> LDAPInjectionAnalysis:
        self._validate(
            url=url,
            params=params,
            body=body,
            headers=headers,
            response_body=response_body,
            parameter_names=parameter_names,
            ldap_query=ldap_query,
            user_controlled_filter=user_controlled_filter,
        )

        indicators: list[LDAPInjectionIndicator] = []

        if params:
            for name, value in params.items():
                lowered_name = name.lower()

                if lowered_name in self.LDAP_PARAMETERS:
                    indicators.append(
                        LDAPInjectionIndicator(
                            type=self.LDAP_PARAMETERS[lowered_name],
                            evidence=f"LDAP-related parameter: {name}",
                            name=name,
                            value=value,
                        )
                    )

                if any(marker in lowered_name for marker in self.LDAP_MARKERS):
                    indicators.append(
                        LDAPInjectionIndicator(
                            type=LDAPInjectionIndicatorType.LDAP_MARKER,
                            evidence=(
                                f"LDAP-related marker in parameter: {name}"
                            ),
                            name=name,
                            value=value,
                        )
                    )

                indicators.extend(
                    self._value_indicators(
                        value=value,
                        name=name,
                    )
                )

        if parameter_names:
            for name in parameter_names:
                lowered_name = name.lower()

                if any(marker in lowered_name for marker in self.LDAP_MARKERS):
                    indicators.append(
                        LDAPInjectionIndicator(
                            type=LDAPInjectionIndicatorType.LDAP_MARKER,
                            evidence=(
                                f"LDAP-related parameter name: {name}"
                            ),
                            name=name,
                        )
                    )

        if url:
            indicators.extend(
                self._value_indicators(
                    value=unquote(url),
                    name="url",
                )
            )

        if body is not None:
            body_text = (
                body.decode("utf-8", errors="replace")
                if isinstance(body, bytes)
                else body
            )
            indicators.extend(
                self._value_indicators(
                    value=body_text,
                    name="body",
                )
            )

        if headers:
            for name, value in headers.items():
                indicators.extend(
                    self._value_indicators(
                        value=value,
                        name=name,
                    )
                )

        if ldap_query is not None:
            indicators.append(
                LDAPInjectionIndicator(
                    type=LDAPInjectionIndicatorType.USER_CONTROLLED_FILTER,
                    evidence="LDAP query/filter supplied for analysis",
                    name="ldap_query",
                    value=ldap_query,
                )
            )
            indicators.extend(
                self._value_indicators(
                    value=ldap_query,
                    name="ldap_query",
                )
            )

        if response_body is not None:
            response_text = (
                response_body.decode("utf-8", errors="replace")
                if isinstance(response_body, bytes)
                else response_body
            )
            lowered = response_text.lower()

            if any(marker in lowered for marker in self.ERROR_MARKERS):
                indicators.append(
                    LDAPInjectionIndicator(
                        type=LDAPInjectionIndicatorType.LDAP_ERROR,
                        evidence=(
                            "Response contains LDAP/filter error markers"
                        ),
                        name="response_body",
                        value=response_text,
                    )
                )

            if any(marker in lowered for marker in self.RESULT_MARKERS):
                indicators.append(
                    LDAPInjectionIndicator(
                        type=LDAPInjectionIndicatorType.LDAP_RESULT,
                        evidence=(
                            "Response contains LDAP-related result markers"
                        ),
                        name="response_body",
                        value=response_text,
                    )
                )

        if user_controlled_filter is True:
            indicators.append(
                LDAPInjectionIndicator(
                    type=LDAPInjectionIndicatorType.USER_CONTROLLED_FILTER,
                    evidence="Explicit user-controlled LDAP filter indicator",
                    name="user_controlled_filter",
                    value="true",
                )
            )

        return LDAPInjectionAnalysis(
            indicators=tuple(indicators)
        )

    def _value_indicators(
        self,
        *,
        value: str,
        name: str,
    ) -> list[LDAPInjectionIndicator]:
        indicators: list[LDAPInjectionIndicator] = []

        if "*" in value:
            indicators.append(
                LDAPInjectionIndicator(
                    type=LDAPInjectionIndicatorType.WILDCARD,
                    evidence="LDAP wildcard detected: *",
                    name=name,
                    value=value,
                )
            )

        if any(operator in value for operator in self.GROUPING_OPERATORS):
            indicators.append(
                LDAPInjectionIndicator(
                    type=LDAPInjectionIndicatorType.GROUPING_OPERATOR,
                    evidence="LDAP grouping syntax detected",
                    name=name,
                    value=value,
                )
            )

        if any(operator in value for operator in self.LOGICAL_OPERATORS):
            indicators.append(
                LDAPInjectionIndicator(
                    type=LDAPInjectionIndicatorType.LOGICAL_OPERATOR,
                    evidence="LDAP logical operator detected",
                    name=name,
                    value=value,
                )
            )

        if any(operator in value for operator in self.ATTRIBUTE_OPERATORS):
            indicators.append(
                LDAPInjectionIndicator(
                    type=LDAPInjectionIndicatorType.ATTRIBUTE_OPERATOR,
                    evidence="LDAP attribute operator detected",
                    name=name,
                    value=value,
                )
            )

        if any(sequence in value.lower() for sequence in self.ESCAPE_SEQUENCES):
            indicators.append(
                LDAPInjectionIndicator(
                    type=LDAPInjectionIndicatorType.LDAP_ESCAPE_SEQUENCE,
                    evidence="LDAP escape sequence detected",
                    name=name,
                    value=value,
                )
            )

        if (
            "(" in value
            and ")"
            in value
        ):
            indicators.append(
                LDAPInjectionIndicator(
                    type=LDAPInjectionIndicatorType.FILTER_SYNTAX,
                    evidence="LDAP filter syntax detected",
                    name=name,
                    value=value,
                )
            )

        return indicators

    @staticmethod
    def _validate(
        *,
        url,
        params,
        body,
        headers,
        response_body,
        parameter_names,
        ldap_query,
        user_controlled_filter,
    ) -> None:
        if url is not None and not isinstance(url, str):
            raise TypeError("url must be a string or None")

        if params is not None and not isinstance(params, dict):
            raise TypeError("params must be a dictionary or None")

        if body is not None and not isinstance(body, (str, bytes)):
            raise TypeError("body must be str, bytes, or None")

        if headers is not None and not isinstance(headers, dict):
            raise TypeError("headers must be a dictionary or None")

        if response_body is not None and not isinstance(
            response_body, (str, bytes)
        ):
            raise TypeError("response_body must be str, bytes, or None")

        if parameter_names is not None and not isinstance(
            parameter_names, (list, tuple)
        ):
            raise TypeError("parameter_names must be a list, tuple, or None")

        if ldap_query is not None and not isinstance(ldap_query, str):
            raise TypeError("ldap_query must be a string or None")

        if user_controlled_filter is not None and not isinstance(
            user_controlled_filter, bool
        ):
            raise TypeError(
                "user_controlled_filter must be a boolean or None"
            )
