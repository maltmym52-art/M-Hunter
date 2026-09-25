from m_hunter.analyzers.graphql import (
    GraphQLAnalysis,
    GraphQLIndicatorType,
)
from m_hunter.core.finding import Finding


class GraphQLFindingAnalyzer:
    METADATA = {
        GraphQLIndicatorType.INTROSPECTION_ENABLED: (
            "Medium",
            "High",
            "GraphQL introspection is enabled. This may expose "
            "schema details, types, fields, and operations that "
            "can assist further security testing.",
        ),
        GraphQLIndicatorType.QUERY_OPERATION: (
            "Info",
            "High",
            "A GraphQL query operation was detected.",
        ),
        GraphQLIndicatorType.MUTATION_OPERATION: (
            "Info",
            "High",
            "A GraphQL mutation operation was detected.",
        ),
        GraphQLIndicatorType.SUBSCRIPTION_OPERATION: (
            "Info",
            "High",
            "A GraphQL subscription operation was detected.",
        ),
        GraphQLIndicatorType.ALIAS_USAGE: (
            "Low",
            "Medium",
            "GraphQL alias usage was detected. Aliases can be relevant "
            "to query complexity and authorization testing.",
        ),
        GraphQLIndicatorType.BATCHING: (
            "Medium",
            "Medium",
            "GraphQL batching was detected. Multiple operations in one "
            "request may require rate-limit and authorization validation.",
        ),
        GraphQLIndicatorType.DEEP_QUERY: (
            "Medium",
            "Medium",
            "A deeply nested GraphQL query was detected. Excessive query "
            "depth can contribute to resource exhaustion.",
        ),
        GraphQLIndicatorType.LARGE_QUERY: (
            "Low",
            "Medium",
            "A large GraphQL query was detected. Query-size limits "
            "should be validated to reduce resource-exhaustion risk.",
        ),
        GraphQLIndicatorType.SENSITIVE_FIELD: (
            "Medium",
            "Medium",
            "A potentially sensitive GraphQL field was detected. "
            "Authorization and data-exposure controls should be "
            "validated for the affected field.",
        ),
    }

    REMEDIATION = (
        "Apply appropriate GraphQL security controls based on the "
        "identified behavior. Restrict or disable introspection where "
        "appropriate, enforce authorization at resolver level, apply "
        "query depth and complexity limits, control batching and rate "
        "limits, and avoid exposing sensitive fields unnecessarily."
    )

    def analyze(
        self,
        analysis: GraphQLAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, GraphQLAnalysis):
            raise TypeError(
                "analysis must be a GraphQLAnalysis instance"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        findings: list[Finding] = []

        grouped = {}

        for indicator in analysis.indicators:
            grouped.setdefault(indicator.type, []).append(
                indicator
            )

        for indicator_type, indicators in grouped.items():
            metadata = self.METADATA.get(indicator_type)

            if metadata is None:
                continue

            severity, confidence, description = metadata

            evidence_lines = [
                f"Indicator type: {indicator_type.value}",
                f"Evidence count: {len(indicators)}",
            ]

            for indicator in indicators:
                evidence_lines.append(
                    f"Evidence: {indicator.evidence}"
                )

                if indicator.name:
                    evidence_lines.append(
                        f"Name: {indicator.name}"
                    )

                if indicator.position is not None:
                    evidence_lines.append(
                        f"Position: {indicator.position}"
                    )

            findings.append(
                Finding(
                    title=(
                        "GraphQL security indicator: "
                        f"{indicator_type.value.replace('_', ' ')}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=(
                        f"{description} Further validation is required "
                        "to determine whether the observed behavior "
                        "represents an exploitable security issue."
                    ),
                    evidence="\n".join(evidence_lines),
                    remediation=self.REMEDIATION,
                    cwe="CWE-200",
                    owasp="API8:2023",
                )
            )

        return findings
