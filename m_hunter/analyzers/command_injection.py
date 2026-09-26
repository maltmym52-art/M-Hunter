from dataclasses import dataclass
from enum import Enum
from urllib.parse import unquote


class CommandInjectionIndicatorType(str, Enum):
    COMMAND_PARAMETER = "command_parameter"
    SHELL_PARAMETER = "shell_parameter"
    EXECUTION_PARAMETER = "execution_parameter"
    COMMAND_MARKER = "command_marker"
    SHELL_MARKER = "shell_marker"
    COMMAND_SEPARATOR = "command_separator"
    PIPE_OPERATOR = "pipe_operator"
    REDIRECTION_OPERATOR = "redirection_operator"
    COMMAND_SUBSTITUTION = "command_substitution"
    BACKTICK_SUBSTITUTION = "backtick_substitution"
    COMMAND_OUTPUT = "command_output"
    EXECUTION_ERROR = "execution_error"
    TIME_DELAY_INDICATOR = "time_delay_indicator"


@dataclass(frozen=True)
class CommandInjectionIndicator:
    type: CommandInjectionIndicatorType
    evidence: str
    name: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class CommandInjectionAnalysis:
    indicators: tuple[CommandInjectionIndicator, ...]

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def types(self) -> set[CommandInjectionIndicatorType]:
        return {indicator.type for indicator in self.indicators}

    @property
    def names(self) -> set[str]:
        return {
            indicator.name
            for indicator in self.indicators
            if indicator.name is not None
        }

    def has_type(self, indicator_type: CommandInjectionIndicatorType) -> bool:
        return indicator_type in self.types


class CommandInjectionAnalyzer:
    COMMAND_PARAMETERS = {
        "cmd": CommandInjectionIndicatorType.COMMAND_PARAMETER,
        "command": CommandInjectionIndicatorType.COMMAND_PARAMETER,
        "exec": CommandInjectionIndicatorType.EXECUTION_PARAMETER,
        "execute": CommandInjectionIndicatorType.EXECUTION_PARAMETER,
        "command_exec": CommandInjectionIndicatorType.EXECUTION_PARAMETER,
        "shell": CommandInjectionIndicatorType.SHELL_PARAMETER,
        "shell_cmd": CommandInjectionIndicatorType.SHELL_PARAMETER,
        "run": CommandInjectionIndicatorType.EXECUTION_PARAMETER,
        "run_cmd": CommandInjectionIndicatorType.EXECUTION_PARAMETER,
    }

    COMMAND_MARKERS = (
        "command",
        "exec",
        "execute",
        "shell",
        "system",
        "popen",
        "subprocess",
    )

    SEPARATORS = (";", "&&", "||")
    PIPE_OPERATORS = ("|",)
    REDIRECTION_OPERATORS = (">", ">>", "<")
    SUBSTITUTION_MARKERS = ("$(", "${")
    BACKTICK_MARKER = "`"

    OUTPUT_MARKERS = (
        "uid=",
        "gid=",
        "root:",
        "www-data",
        "command not found",
        "permission denied",
        "no such file or directory",
    )

    ERROR_MARKERS = (
        "shell error",
        "execution failed",
        "exec failed",
        "command failed",
        "subprocess error",
        "system()",
        "popen()",
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
        command_execution: bool | None = None,
        time_delay: bool | None = None,
    ) -> CommandInjectionAnalysis:
        self._validate(
            url=url,
            params=params,
            body=body,
            headers=headers,
            response_body=response_body,
            parameter_names=parameter_names,
            command_execution=command_execution,
            time_delay=time_delay,
        )

        indicators: list[CommandInjectionIndicator] = []

        if params:
            for name, value in params.items():
                normalized = name.lower()

                if normalized in self.COMMAND_PARAMETERS:
                    indicators.append(
                        CommandInjectionIndicator(
                            type=self.COMMAND_PARAMETERS[normalized],
                            evidence=f"Command-related parameter: {name}",
                            name=name,
                            value=value,
                        )
                    )

                if any(marker in normalized for marker in self.COMMAND_MARKERS):
                    indicators.append(
                        CommandInjectionIndicator(
                            type=CommandInjectionIndicatorType.COMMAND_MARKER,
                            evidence=f"Command execution marker in parameter: {name}",
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
                lowered = name.lower()

                if any(marker in lowered for marker in self.COMMAND_MARKERS):
                    indicators.append(
                        CommandInjectionIndicator(
                            type=CommandInjectionIndicatorType.COMMAND_MARKER,
                            evidence=f"Command-related parameter name: {name}",
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

        if response_body is not None:
            response_text = (
                response_body.decode("utf-8", errors="replace")
                if isinstance(response_body, bytes)
                else response_body
            )
            lowered = response_text.lower()

            if any(marker in lowered for marker in self.OUTPUT_MARKERS):
                indicators.append(
                    CommandInjectionIndicator(
                        type=CommandInjectionIndicatorType.COMMAND_OUTPUT,
                        evidence="Response contains command-execution-related output",
                        name="response_body",
                        value=response_text,
                    )
                )

            if any(marker in lowered for marker in self.ERROR_MARKERS):
                indicators.append(
                    CommandInjectionIndicator(
                        type=CommandInjectionIndicatorType.EXECUTION_ERROR,
                        evidence="Response contains command-execution error markers",
                        name="response_body",
                        value=response_text,
                    )
                )

        if command_execution is True:
            indicators.append(
                CommandInjectionIndicator(
                    type=CommandInjectionIndicatorType.COMMAND_OUTPUT,
                    evidence="Explicit command execution indicator",
                    name="command_execution",
                    value="true",
                )
            )

        if time_delay is True:
            indicators.append(
                CommandInjectionIndicator(
                    type=CommandInjectionIndicatorType.TIME_DELAY_INDICATOR,
                    evidence="Explicit time-delay behavior indicator",
                    name="time_delay",
                    value="true",
                )
            )

        return CommandInjectionAnalysis(
            indicators=tuple(indicators)
        )

    def _value_indicators(
        self,
        *,
        value: str,
        name: str,
    ) -> list[CommandInjectionIndicator]:
        indicators: list[CommandInjectionIndicator] = []

        for separator in self.SEPARATORS:
            if separator in value:
                indicators.append(
                    CommandInjectionIndicator(
                        type=CommandInjectionIndicatorType.COMMAND_SEPARATOR,
                        evidence=f"Command separator detected: {separator}",
                        name=name,
                        value=value,
                    )
                )
                break

        for operator in self.PIPE_OPERATORS:
            if operator in value:
                indicators.append(
                    CommandInjectionIndicator(
                        type=CommandInjectionIndicatorType.PIPE_OPERATOR,
                        evidence=f"Pipe operator detected: {operator}",
                        name=name,
                        value=value,
                    )
                )
                break

        for operator in self.REDIRECTION_OPERATORS:
            if operator in value:
                indicators.append(
                    CommandInjectionIndicator(
                        type=CommandInjectionIndicatorType.REDIRECTION_OPERATOR,
                        evidence=f"Redirection operator detected: {operator}",
                        name=name,
                        value=value,
                    )
                )
                break

        for marker in self.SUBSTITUTION_MARKERS:
            if marker in value:
                indicators.append(
                    CommandInjectionIndicator(
                        type=CommandInjectionIndicatorType.COMMAND_SUBSTITUTION,
                        evidence=f"Command substitution marker detected: {marker}",
                        name=name,
                        value=value,
                    )
                )
                break

        if self.BACKTICK_MARKER in value:
            indicators.append(
                CommandInjectionIndicator(
                    type=CommandInjectionIndicatorType.BACKTICK_SUBSTITUTION,
                    evidence="Backtick command substitution detected",
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
        command_execution,
        time_delay,
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

        if command_execution is not None and not isinstance(
            command_execution, bool
        ):
            raise TypeError("command_execution must be a boolean or None")

        if time_delay is not None and not isinstance(time_delay, bool):
            raise TypeError("time_delay must be a boolean or None")
