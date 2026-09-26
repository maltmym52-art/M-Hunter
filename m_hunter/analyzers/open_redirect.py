from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qs, urlparse


class OpenRedirectIndicatorType(str, Enum):
    REDIRECT_PARAMETER = "redirect_parameter"
    URL_PARAMETER = "url_parameter"
    RETURN_URL_PARAMETER = "return_url_parameter"
    NEXT_PARAMETER = "next_parameter"
    CONTINUE_PARAMETER = "continue_parameter"
    DESTINATION_PARAMETER = "destination_parameter"
    EXTERNAL_URL = "external_url"
    ABSOLUTE_URL = "absolute_url"
    PROTOCOL_RELATIVE_URL = "protocol_relative_url"
    EXTERNAL_HOST = "external_host"
    REDIRECT_RESPONSE = "redirect_response"
    LOCATION_HEADER = "location_header"
    USER_CONTROLLED_DESTINATION = "user_controlled_destination"


@dataclass(frozen=True)
class OpenRedirectIndicator:
    type: OpenRedirectIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass
class OpenRedirectAnalysis:
    indicators: list[OpenRedirectIndicator]

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> list[OpenRedirectIndicatorType]:
        return list(dict.fromkeys(i.type for i in self.indicators))

    @property
    def names(self) -> list[str]:
        return list(
            dict.fromkeys(
                i.name for i in self.indicators if i.name is not None
            )
        )

    def has_type(
        self,
        indicator_type: OpenRedirectIndicatorType,
    ) -> bool:
        return any(
            indicator.type == indicator_type
            for indicator in self.indicators
        )


class OpenRedirectAnalyzer:
    REDIRECT_PARAMETERS = {
        "redirect": OpenRedirectIndicatorType.REDIRECT_PARAMETER,
        "redirect_uri": OpenRedirectIndicatorType.REDIRECT_PARAMETER,
        "redirect_url": OpenRedirectIndicatorType.REDIRECT_PARAMETER,
        "url": OpenRedirectIndicatorType.URL_PARAMETER,
        "return": OpenRedirectIndicatorType.RETURN_URL_PARAMETER,
        "return_url": OpenRedirectIndicatorType.RETURN_URL_PARAMETER,
        "returnurl": OpenRedirectIndicatorType.RETURN_URL_PARAMETER,
        "next": OpenRedirectIndicatorType.NEXT_PARAMETER,
        "next_url": OpenRedirectIndicatorType.NEXT_PARAMETER,
        "continue": OpenRedirectIndicatorType.CONTINUE_PARAMETER,
        "continue_url": OpenRedirectIndicatorType.CONTINUE_PARAMETER,
        "destination": OpenRedirectIndicatorType.DESTINATION_PARAMETER,
        "dest": OpenRedirectIndicatorType.DESTINATION_PARAMETER,
    }

    def analyze(
        self,
        *,
        url: str | None = None,
        params: dict[str, str] | None = None,
        location: str | None = None,
        status_code: int | None = None,
        headers: dict[str, str] | None = None,
        target_host: str | None = None,
    ) -> OpenRedirectAnalysis:
        if url is not None and not isinstance(url, str):
            raise TypeError("url must be a string or None")

        if params is not None and not isinstance(params, dict):
            raise TypeError("params must be a dictionary or None")

        if location is not None and not isinstance(location, str):
            raise TypeError("location must be a string or None")

        if status_code is not None and not isinstance(status_code, int):
            raise TypeError("status_code must be an integer or None")

        if headers is not None and not isinstance(headers, dict):
            raise TypeError("headers must be a dictionary or None")

        if target_host is not None and not isinstance(target_host, str):
            raise TypeError("target_host must be a string or None")

        indicators: list[OpenRedirectIndicator] = []

        def inspect_destination(
            name: str,
            value: str,
        ) -> None:
            value = value.strip()

            if not value:
                return

            parsed = urlparse(value)

            if parsed.scheme and parsed.netloc:
                indicators.append(
                    OpenRedirectIndicator(
                        OpenRedirectIndicatorType.ABSOLUTE_URL,
                        f"Absolute URL supplied by parameter '{name}': {value}",
                        name=name,
                        value=value,
                    )
                )

                if target_host:
                    if parsed.hostname and (
                        parsed.hostname.lower()
                        != target_host.lower()
                    ):
                        indicators.append(
                            OpenRedirectIndicator(
                                OpenRedirectIndicatorType.EXTERNAL_HOST,
                                (
                                    f"Parameter '{name}' points to an "
                                    f"external host: {parsed.hostname}"
                                ),
                                name=name,
                                value=value,
                            )
                        )
                else:
                    indicators.append(
                        OpenRedirectIndicator(
                            OpenRedirectIndicatorType.EXTERNAL_URL,
                            (
                                f"External absolute URL supplied by "
                                f"parameter '{name}'."
                            ),
                            name=name,
                            value=value,
                        )
                    )

            elif value.startswith("//"):
                indicators.append(
                    OpenRedirectIndicator(
                        OpenRedirectIndicatorType.PROTOCOL_RELATIVE_URL,
                        (
                            f"Protocol-relative destination supplied "
                            f"by parameter '{name}': {value}"
                        ),
                        name=name,
                        value=value,
                    )
                )

            if (
                value.startswith("http://")
                or value.startswith("https://")
                or value.startswith("//")
            ):
                indicators.append(
                    OpenRedirectIndicator(
                        OpenRedirectIndicatorType.USER_CONTROLLED_DESTINATION,
                        (
                            f"User-controlled redirect destination "
                            f"detected in '{name}'."
                        ),
                        name=name,
                        value=value,
                    )
                )

        if url:
            parsed_url = urlparse(url)

            for name, values in parse_qs(
                parsed_url.query,
                keep_blank_values=True,
            ).items():
                parameter_name = name.lower()

                indicator_type = self.REDIRECT_PARAMETERS.get(
                    parameter_name
                )

                if indicator_type is not None:
                    for value in values:
                        indicators.append(
                            OpenRedirectIndicator(
                                indicator_type,
                                (
                                    f"Redirect-related parameter "
                                    f"detected: {name}"
                                ),
                                name=name,
                                value=value,
                            )
                        )
                        inspect_destination(name, value)

        if params:
            for name, value in params.items():
                parameter_name = name.lower()

                indicator_type = self.REDIRECT_PARAMETERS.get(
                    parameter_name
                )

                if indicator_type is not None:
                    indicators.append(
                        OpenRedirectIndicator(
                            indicator_type,
                            (
                                f"Redirect-related parameter "
                                f"detected: {name}"
                            ),
                            name=name,
                            value=value,
                        )
                    )
                    inspect_destination(name, value)

        if location:
            indicators.append(
                OpenRedirectIndicator(
                    OpenRedirectIndicatorType.LOCATION_HEADER,
                    f"Location header detected: {location}",
                    value=location,
                )
            )

            inspect_destination("Location", location)

        if headers:
            for name, value in headers.items():
                if name.lower() == "location":
                    indicators.append(
                        OpenRedirectIndicator(
                            OpenRedirectIndicatorType.LOCATION_HEADER,
                            f"Location header detected: {value}",
                            name=name,
                            value=value,
                        )
                    )

                    inspect_destination(name, value)

        if status_code is not None and 300 <= status_code < 400:
            indicators.append(
                OpenRedirectIndicator(
                    OpenRedirectIndicatorType.REDIRECT_RESPONSE,
                    f"HTTP redirect response detected: {status_code}",
                    value=str(status_code),
                )
            )

        return OpenRedirectAnalysis(
            indicators=indicators,
        )
