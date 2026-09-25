from dataclasses import dataclass, field

from m_hunter.analyzers.graphql import GraphQLAnalysis
from m_hunter.validation.graphql import GraphQLValidationResult


@dataclass
class GraphQLPipelineResult:
    validation: GraphQLValidationResult
    accepted: bool
    findings: list[str] = field(default_factory=list)


class GraphQLValidationPipeline:
    def process(
        self,
        analysis: GraphQLAnalysis,
        validation: GraphQLValidationResult,
    ) -> GraphQLPipelineResult:
        if not isinstance(analysis, GraphQLAnalysis):
            raise TypeError(
                "analysis must be a GraphQLAnalysis instance"
            )

        if not isinstance(
            validation,
            GraphQLValidationResult,
        ):
            raise TypeError(
                "validation must be a GraphQLValidationResult instance"
            )

        accepted = (
            analysis.detected
            and (
                validation.potential_graphql_issue
                or validation.behavior_changed
            )
        )

        findings: list[str] = []

        if accepted:
            findings.append(
                "GraphQL behavior requires further security validation."
            )

        return GraphQLPipelineResult(
            validation=validation,
            accepted=accepted,
            findings=findings,
        )
