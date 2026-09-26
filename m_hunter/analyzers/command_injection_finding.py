from collections import defaultdict

from m_hunter.analyzers.command_injection import (
    CommandInjectionAnalysis,
    CommandInjectionIndicatorType,
)
from m_hunter.core.finding import Finding


class CommandInjectionFindingAnalyzer:
    METADATA = {
        CommandInjectionIndicatorType.COMMAND_PARAMETER: (
            "Command-related parameter",
            "Info",
            "High",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.SHELL_PARAMETER: (
            "Shell-related parameter",
            "Info",
            "High",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.EXECUTION_PARAMETER: (
            "Command execution parameter",
            "Low",
            "High",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.COMMAND_MARKER: (
            "Command execution marker",
            "Info",
            "Medium",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.SHELL_MARKER: (
            "Shell marker",
            "Info",
            "Medium",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.COMMAND_SEPARATOR: (
            "Command separator detected",
            "Medium",
            "Medium",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.PIPE_OPERATOR: (
            "Command pipe operator detected",
            "Medium",
            "Medium",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.REDIRECTION_OPERATOR: (
            "Command redirection operator detected",
            "Medium",
            "Medium",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.COMMAND_SUBSTITUTION: (
            "Command substitution detected",
            "High",
            "Medium",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.BACKTICK_SUBSTITUTION: (
            "Backtick command substitution detected",
            "High",
            "Medium",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.COMMAND_OUTPUT: (
            "Possible command execution output",
            "High",
            "High",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.EXECUTION_ERROR: (
            "Possible command execution error",
            "Medium",
            "High",
            "CWE-78",
            "A03:2021",
        ),
        CommandInjectionIndicatorType.TIME_DELAY_INDICATOR: (
            "Possible command execution time delay",
            "High",
            "Medium",
            "CWE-78",
            "A03:2021",
        ),
    }

    def analyze(
        self,
        *,
        analysis: CommandInjectionAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, CommandInjectionAnalysis):
            raise TypeError(
                "analysis must be a CommandInjectionAnalysis"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        grouped = defaultdict(list)

        for indicator in analysis.indicators:
            grouped[indicator.type].append(indicator)

        findings: list[Finding] = []

        for indicator_type, indicators in grouped.items():
            metadata = self.METADATA.get(indicator_type)

            if metadata is None:
                continue

            title, severity, confidence, cwe, owasp = metadata

            evidence = "\n".join(
                (
                    f"- {indicator.evidence}"
                    + (
                        f" Value: {indicator.value}"
                        if indicator.value is not None
                        else ""
                    )
                )
                for indicator in indicators
            )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=(
                        "Command-injection-related indicators were detected. "
                        "Indicator presence alone does not prove command "
                        "injection; controlled validation is required."
                    ),
                    evidence=evidence,
                    remediation=(
                        "Avoid passing user-controlled input to operating "
                        "system commands. Prefer safe APIs instead of shell "
                        "execution, use strict allowlists and input "
                        "validation, avoid shell interpretation, and apply "
                        "least-privilege execution."
                    ),
                    cwe=cwe,
                    owasp=owasp,
                )
            )

        return findings
