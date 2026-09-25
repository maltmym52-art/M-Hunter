from m_hunter.analyzers.deserialization import (
    DeserializationAnalysis,
    DeserializationIndicatorType,
)
from m_hunter.core.finding import Finding


class DeserializationFindingAnalyzer:
    METADATA = {
        DeserializationIndicatorType.SERIALIZED_CONTENT_TYPE: (
            "High",
            "Medium",
            "Serialized content type detected; unsafe deserialization "
            "may be possible if attacker-controlled data is processed.",
        ),
        DeserializationIndicatorType.SERIALIZED_COOKIE: (
            "High",
            "Medium",
            "Serialization-related cookie detected; server-side "
            "deserialization of attacker-controlled state may be possible.",
        ),
        DeserializationIndicatorType.SERIALIZED_PARAMETER: (
            "High",
            "Medium",
            "Serialization-related parameter detected; attacker-controlled "
            "serialized data may reach a deserialization sink.",
        ),
        DeserializationIndicatorType.SERIALIZED_FILE: (
            "Medium",
            "Medium",
            "Serialized file type detected; unsafe deserialization may "
            "occur if uploaded or processed by the application.",
        ),
        DeserializationIndicatorType.SERIALIZATION_HEADER: (
            "Medium",
            "Medium",
            "Serialization-related HTTP header detected; further validation "
            "is required to determine whether serialized data is deserialized.",
        ),
    }

    REMEDIATION = (
        "Avoid deserializing untrusted data. Prefer safe, structured data "
        "formats with strict schemas and validation. Apply integrity "
        "protection where serialized state must be accepted, restrict "
        "permitted classes or types, and keep serialization libraries "
        "securely configured and updated."
    )

    def analyze(
        self,
        analysis: DeserializationAnalysis,
        target: str,
        endpoint: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, DeserializationAnalysis):
            raise TypeError(
                "analysis must be a DeserializationAnalysis instance"
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must not be empty")

        if endpoint is not None and not isinstance(endpoint, str):
            raise TypeError("endpoint must be a string or None")

        findings: list[Finding] = []

        grouped: dict[
            DeserializationIndicatorType,
            list,
        ] = {}

        for indicator in analysis.indicators:
            grouped.setdefault(indicator.type, []).append(indicator)

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

            smuggling_description = (
                f"{description} "
                "The current evidence identifies an input or protocol "
                "pattern associated with serialized data, but does not "
                "by itself prove unsafe deserialization. Further validation "
                "is required to determine whether attacker-controlled data "
                "reaches an unsafe deserialization sink."
            )

            findings.append(
                Finding(
                    title=(
                        "Potential insecure deserialization: "
                        f"{indicator_type.value.replace('_', ' ')}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    target=target,
                    endpoint=endpoint,
                    description=smuggling_description,
                    evidence="\n".join(evidence_lines),
                    remediation=self.REMEDIATION,
                    cwe="CWE-502",
                    owasp="A08:2021",
                )
            )

        return findings
