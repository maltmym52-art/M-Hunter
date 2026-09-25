from m_hunter.analyzers.finding import FindingAnalyzer
from m_hunter.analyzers.xss import XSSAnalysis, XSSContext
from m_hunter.core.finding import Finding


class XSSFindingAnalyzer(FindingAnalyzer):
    name = "xss_findings"
    description = "Converts XSS reflection analysis into findings"

    CONTEXT_METADATA = {
        XSSContext.HTML_TEXT: {
            "title": "Reflected Input in HTML Context",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "Controlled input was reflected in an HTML text "
                "context. Reflection alone does not prove script "
                "execution."
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
                "Controlled input was reflected inside an HTML "
                "attribute context."
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
                "Controlled input was reflected inside a JavaScript "
                "context. Additional validation is required to "
                "determine whether script execution is possible."
            ),
            "remediation": (
                "Avoid inserting untrusted data into executable "
                "JavaScript contexts. Use safe data serialization "
                "and context-aware encoding."
            ),
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
        XSSContext.URL: {
            "title": "Reflected Input in URL Context",
            "severity": "Medium",
            "confidence": "Medium",
            "description": (
                "Controlled input was reflected in a URL-bearing "
                "HTML attribute."
            ),
            "remediation": (
                "Validate URLs against an allowlist and apply "
                "appropriate URL and HTML attribute encoding."
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
                "Avoid inserting untrusted data into CSS contexts "
                "and apply context-specific encoding."
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
                "Ensure JSON data is serialized safely and is not "
                "inserted directly into executable browser contexts."
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
                "Validate and safely encode untrusted data before "
                "including it in responses."
            ),
            "cwe": "CWE-79",
            "owasp": "A03:2021",
        },
    }

    def analyze(
        self,
        analysis: XSSAnalysis,
        *,
        target: str,
        endpoint: str | None = None,
        parameter: str | None = None,
    ) -> list[Finding]:
        if not isinstance(analysis, XSSAnalysis):
            raise TypeError(
                "analysis must be an instance of XSSAnalysis"
            )

        if not analysis.reflected:
            return []

        findings: list[Finding] = []

        for context in analysis.contexts:
            metadata = self.CONTEXT_METADATA.get(context)

            if metadata is None:
                continue

            reflections = [
                reflection
                for reflection in analysis.reflections
                if reflection.context == context
            ]

            encoded_count = sum(
                reflection.encoded
                for reflection in reflections
            )

            evidence = (
                f"Controlled marker {analysis.marker!r} was reflected "
                f"in {context.value} context at "
                f"{endpoint or target}. "
                f"Reflection count: {len(reflections)}. "
                f"Encoded reflections: {encoded_count}."
            )

            findings.append(
                self.create_finding(
                    title=metadata["title"],
                    severity=metadata["severity"],
                    confidence=metadata["confidence"],
                    target=target,
                    endpoint=endpoint or target,
                    parameter=parameter,
                    description=metadata["description"],
                    evidence=evidence,
                    remediation=metadata["remediation"],
                    cwe=metadata["cwe"],
                    owasp=metadata["owasp"],
                )
            )

        return findings
