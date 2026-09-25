from m_hunter.analyzers.authorization import (
    AuthorizationAnalysis,
    AuthorizationAnalyzer,
)
from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.core.finding import Finding


class AuthorizationFindingAnalyzer(FindingAnalyzer):
    name = "authorization_findings"
    description = "Converts authorization analysis into findings"

    def analyze(
        self,
        analysis: AuthorizationAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(
            analysis,
            AuthorizationAnalysis,
        ):
            raise TypeError(
                "analysis must be an AuthorizationAnalysis"
            )

        # The presence of an authorization mechanism or a resource
        # identifier is contextual information, not proof of an
        # authorization vulnerability. IDOR/BOLA requires comparison
        # and validation across authorization contexts.
        return []

    def analyze_http(
        self,
        http_analysis,
        *,
        target: str | None = None,
        endpoint: str | None = None,
    ) -> list[Finding]:
        analyzer = AuthorizationAnalyzer()
        analysis = analyzer.analyze(http_analysis)

        resolved_target = (
            target or http_analysis.response.url
        )
        resolved_endpoint = (
            endpoint or http_analysis.response.url
        )

        return self.analyze(
            analysis,
            target=resolved_target,
            endpoint=resolved_endpoint,
        )
