from dataclasses import dataclass

from m_hunter.analyzers.subdomain_takeover import (
    SubdomainTakeoverAnalysis,
    SubdomainTakeoverIndicatorType,
)


@dataclass(frozen=True)
class SubdomainTakeoverValidationResult:
    dns_target_present: bool
    external_cname: bool
    unresolved_target: bool
    nxdomain: bool
    service_fingerprint: bool
    takeover_signature: bool
    response_changed: bool
    security_indicator_present: bool
    potential_subdomain_takeover: bool
    status: str
    evidence: str


class SubdomainTakeoverValidator:
    STRONG_INDICATORS = {
        SubdomainTakeoverIndicatorType.CNAME_DANGLING,
        SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE,
    }

    SUPPORTING_INDICATORS = {
        SubdomainTakeoverIndicatorType.CNAME_EXTERNAL,
        SubdomainTakeoverIndicatorType.NXDOMAIN,
        SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET,
        SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT,
        SubdomainTakeoverIndicatorType.HOST_NOT_FOUND,
        SubdomainTakeoverIndicatorType.RESOURCE_NOT_FOUND,
    }

    def validate(
        self,
        analysis: SubdomainTakeoverAnalysis,
        *,
        dns_target_present: bool = False,
        response_changed: bool = False,
    ) -> SubdomainTakeoverValidationResult:
        types = set(analysis.types)

        external_cname = (
            SubdomainTakeoverIndicatorType.CNAME_EXTERNAL in types
        )

        unresolved_target = (
            SubdomainTakeoverIndicatorType.UNRESOLVED_TARGET in types
        )

        nxdomain = (
            SubdomainTakeoverIndicatorType.NXDOMAIN in types
        )

        service_fingerprint = (
            SubdomainTakeoverIndicatorType.SERVICE_FINGERPRINT in types
        )

        takeover_signature = (
            SubdomainTakeoverIndicatorType.TAKEOVER_SIGNATURE in types
        )

        security_indicator_present = bool(
            types & (
                self.STRONG_INDICATORS
                | self.SUPPORTING_INDICATORS
            )
        )

        strong_evidence = bool(
            types & self.STRONG_INDICATORS
        )

        dns_condition = (
            external_cname
            and (unresolved_target or nxdomain)
        )

        service_condition = (
            external_cname
            and service_fingerprint
            and (unresolved_target or nxdomain)
        )

        signature_condition = (
            external_cname
            and takeover_signature
        )

        potential_subdomain_takeover = bool(
            analysis.detected
            and security_indicator_present
            and (
                (dns_condition and response_changed)
                or service_condition and response_changed
                or signature_condition
                or (
                    strong_evidence
                    and external_cname
                    and response_changed
                )
            )
        )

        if potential_subdomain_takeover:
            status = "potential"
        elif analysis.detected:
            status = "indicator"
        else:
            status = "clean"

        evidence_parts: list[str] = []

        if dns_target_present:
            evidence_parts.append("DNS target present")

        if external_cname:
            evidence_parts.append("external CNAME detected")

        if unresolved_target:
            evidence_parts.append("CNAME target unresolved")

        if nxdomain:
            evidence_parts.append("NXDOMAIN detected")

        if service_fingerprint:
            evidence_parts.append("third-party service fingerprint detected")

        if takeover_signature:
            evidence_parts.append("takeover signature detected")

        if response_changed:
            evidence_parts.append("HTTP response behavior changed")

        if not evidence_parts:
            evidence_parts.append("no takeover-specific evidence observed")

        return SubdomainTakeoverValidationResult(
            dns_target_present=dns_target_present,
            external_cname=external_cname,
            unresolved_target=unresolved_target,
            nxdomain=nxdomain,
            service_fingerprint=service_fingerprint,
            takeover_signature=takeover_signature,
            response_changed=response_changed,
            security_indicator_present=security_indicator_present,
            potential_subdomain_takeover=potential_subdomain_takeover,
            status=status,
            evidence="; ".join(evidence_parts),
        )
