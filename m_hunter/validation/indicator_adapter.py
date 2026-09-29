"""Bridge existing indicator validators/finding catalogs to unified validation."""

from typing import Any

from m_hunter.analyzers.result import AnalysisResult
from m_hunter.core.target import Target
from m_hunter.validation.analysis import AnalysisValidation, FindingCandidate


class LegacyIndicatorValidator:
    """Adapt legacy per-indicator validators without constructing Findings.

    Existing security decisions and metadata remain authoritative. This class
    only translates those decisions into the current AnalysisValidation model;
    the canonical Finding is still created by FindingConverter.
    """

    def __init__(self, validator: Any, finding_catalog: Any) -> None:
        self.validator = validator
        self.finding_catalog = finding_catalog

    def validate(self, analysis: AnalysisResult, context) -> AnalysisValidation:
        decisions = self.validate_many(analysis, context)
        return next(
            (decision for decision in decisions
             if decision.disposition.value == "finding"),
            decisions[0] if decisions else AnalysisValidation.informational(),
        )

    def validate_many(self, analysis: AnalysisResult, context) -> list[AnalysisValidation]:
        indicators = getattr(analysis.data, "indicators", ()) or ()
        decisions = []
        indicator_names = {
            getattr(getattr(indicator, "type", None), "name",
                    str(getattr(indicator, "type", None)))
            for indicator in indicators
        }
        duplicate_indicators = getattr(
            self.finding_catalog, "DUPLICATE_INDICATORS", {}
        )
        target = context.target
        if isinstance(target, Target):
            target = target.url
        target = target or context.request_url
        for indicator in indicators:
            kind = getattr(indicator, "type", None)
            name = getattr(kind, "name", str(kind))
            if any(
                required in indicator_names
                for required in duplicate_indicators.get(name, ())
            ):
                continue
            policy = self.validator.validate(name)
            if not getattr(policy, "requires_response_change", False):
                continue
            metadata = self.finding_catalog.METADATA.get(name)
            if metadata is None:
                continue
            evidence = getattr(indicator, "value", None) or getattr(indicator, "name", "")
            description = getattr(indicator, "name", "")
            candidate = FindingCandidate(
                title=metadata.get("title"),
                severity=metadata.get("severity"),
                confidence=metadata.get("confidence"),
                target=target,
                endpoint=context.request_url,
                parameter=None,
                description=metadata.get("description", description),
                evidence=str(evidence),
                remediation=metadata.get("remediation", ""),
                cwe=metadata.get("cwe"),
                owasp=metadata.get("owasp"),
                metadata={"indicator": name},
            )
            decisions.append(AnalysisValidation.finding(
                candidate,
                metadata={"legacy_validator_reason": getattr(policy, "reason", "")},
            ))
        if not decisions:
            decisions.append(AnalysisValidation.informational(
                metadata={"reason": "legacy validator classified indicators as informational"}
            ))
        return decisions


def default_security_validators() -> dict[str, LegacyIndicatorValidator]:
    """Existing passive header, cookie, and cache decisions in unified form."""
    from m_hunter.findings.cache_control_security import CacheControlSecurityFinding
    from m_hunter.findings.http_cookie_security import HttpCookieSecurityFinding
    from m_hunter.findings.security_headers_baseline import SecurityHeadersBaselineFinding
    from m_hunter.validation.cache_control_security import CacheControlSecurityValidator
    from m_hunter.validation.http_cookie_security import HttpCookieSecurityValidator
    from m_hunter.validation.security_headers_baseline import SecurityHeadersBaselineValidator

    return {
        "security_headers_baseline": LegacyIndicatorValidator(
            SecurityHeadersBaselineValidator(), SecurityHeadersBaselineFinding
        ),
        "http_cookie_security": LegacyIndicatorValidator(
            HttpCookieSecurityValidator(), HttpCookieSecurityFinding
        ),
        "cache_control_security": LegacyIndicatorValidator(
            CacheControlSecurityValidator(), CacheControlSecurityFinding
        ),
    }
