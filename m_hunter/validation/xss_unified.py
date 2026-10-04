from m_hunter.analyzers.xss import XSSAnalysis, XSSContext
from m_hunter.validation.analysis import AnalysisValidation, FindingCandidate


class XSSUnifiedValidator:
    """Adapt XSS reflection analysis to the unified validation API."""

    METADATA = {
        XSSContext.HTML_TEXT: {
            "title": "Reflected Input in HTML Context",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "Controlled input was reflected in an HTML text context. "
                "Reflection alone does not prove script execution."
            ),
            "remediation": (
                "Apply context-appropriate output encoding and "
                "validate untrusted input before rendering it."
            ),
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        XSSContext.HTML_ATTRIBUTE: {
            "title": "Reflected Input in HTML Attribute Context",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "Controlled input was reflected inside an HTML attribute context."
            ),
            "remediation": (
                "Use context-aware HTML attribute encoding and "
                "avoid constructing attributes from untrusted input."
            ),
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        XSSContext.JAVASCRIPT: {
            "title": "Reflected Input in JavaScript Context",
            "severity": "High",
            "confidence": "Medium",
            "description": (
                "Controlled input was reflected inside a JavaScript context. "
                "Additional validation is required to determine whether "
                "script execution is possible."
            ),
            "remediation": (
                "Avoid inserting untrusted data into executable JavaScript "
                "contexts. Use safe data serialization and context-aware encoding."
            ),
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        XSSContext.URL: {
            "title": "Reflected Input in URL Context",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "Controlled input was reflected in a URL-bearing HTML attribute."
            ),
            "remediation": (
                "Validate URLs against an allowlist and apply appropriate "
                "URL and HTML attribute encoding."
            ),
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        XSSContext.CSS: {
            "title": "Reflected Input in CSS Context",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "Controlled input was reflected in a CSS context."
            ),
            "remediation": (
                "Avoid inserting untrusted data into CSS contexts and apply "
                "context-specific encoding."
            ),
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        XSSContext.JSON: {
            "title": "Reflected Input in JSON Response",
            "severity": "Low",
            "confidence": "Low",
            "description": (
                "Controlled input was reflected in a JSON response. "
                "JSON reflection alone does not establish XSS."
            ),
            "remediation": (
                "Ensure JSON data is serialized safely and is not inserted "
                "directly into executable browser contexts."
            ),
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        XSSContext.TEXT: {
            "title": "Reflected Input",
            "severity": "Low",
            "confidence": "Low",
            "description": (
                "Controlled input was reflected in the response."
            ),
            "remediation": (
                "Validate and safely encode untrusted data before including "
                "it in responses."
            ),
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
    }

    def validate(self, analysis, context) -> AnalysisValidation:
        if not isinstance(analysis.data, XSSAnalysis):
            return AnalysisValidation.invalid(
                "xss analysis data must be an XSSAnalysis"
            )

        xss = analysis.data

        if not xss.reflected:
            return AnalysisValidation.informational(
                metadata={"reason": "controlled marker was not reflected"}
            )

        target = context.target
        target = getattr(target, "url", None) or target or context.request_url
        endpoint = context.request_url or target
        parameter = context.options.get("parameter")

        decisions = []

        for xss_context in xss.contexts:
            metadata = self.METADATA.get(xss_context)
            if metadata is None:
                continue

            reflections = [
                item
                for item in xss.reflections
                if item.context == xss_context
            ]

            encoded_count = sum(
                item.encoded
                for item in reflections
            )

            evidence = (
                f"Controlled marker {xss.marker!r} was reflected "
                f"in {xss_context.value} context at {endpoint}. "
                f"Reflection count: {len(reflections)}. "
                f"Encoded reflections: {encoded_count}."
            )

            decisions.append(
                AnalysisValidation.finding(
                    FindingCandidate(
                        title=metadata["title"],
                        severity=metadata["severity"],
                        confidence=metadata["confidence"],
                        target=str(target),
                        endpoint=str(endpoint),
                        parameter=parameter,
                        description=metadata["description"],
                        evidence=evidence,
                        remediation=metadata["remediation"],
                        cwe=metadata["cwe"],
                        owasp=metadata["owasp"],
                        metadata={
                            "xss_context": xss_context.value,
                            "reflection_count": len(reflections),
                            "encoded_reflection_count": encoded_count,
                            "execution_confirmed": False,
                        },
                    ),
                    metadata={
                        "status": "potential_xss"
                        if xss_context
                        in {
                            XSSContext.HTML_TEXT,
                            XSSContext.HTML_ATTRIBUTE,
                            XSSContext.JAVASCRIPT,
                            XSSContext.URL,
                            XSSContext.CSS,
                        }
                        else "reflection_only",
                    },
                )
            )

        if not decisions:
            return AnalysisValidation.informational(
                metadata={"reason": "no supported XSS reflection context"}
            )

        return decisions[0]
