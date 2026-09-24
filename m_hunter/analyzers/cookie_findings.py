from m_hunter.analyzers.set_cookie import SetCookie
from m_hunter.core.finding import Finding


class CookieSecurityFindings:
    def analyze(
        self,
        cookies: list[SetCookie],
        target: str,
    ) -> list[Finding]:
        if not isinstance(cookies, list):
            raise TypeError(
                "cookies must be a list"
            )

        if not isinstance(target, str):
            raise TypeError(
                "target must be a string"
            )

        target = target.strip()

        if not target:
            raise ValueError(
                "target must not be empty"
            )

        findings: list[Finding] = []

        for cookie in cookies:
            if not isinstance(cookie, SetCookie):
                raise TypeError(
                    "cookies must contain SetCookie instances"
                )

            if not cookie.is_session_cookie:
                continue

            findings.extend(
                self._analyze_session_cookie(
                    cookie,
                    target,
                )
            )

        return findings

    def _analyze_session_cookie(
        self,
        cookie: SetCookie,
        target: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not cookie.secure:
            findings.append(
                Finding(
                    title=(
                        "Session Cookie Missing Secure Attribute"
                    ),
                    severity="medium",
                    confidence="high",
                    target=target,
                    endpoint=target,
                    parameter=cookie.name,
                    description=(
                        "A session cookie is set without "
                        "the Secure attribute."
                    ),
                    evidence=(
                        f"Cookie: {cookie.name}; "
                        "Secure: false"
                    ),
                    remediation=(
                        "Set the Secure attribute on "
                        "session cookies so they are only "
                        "sent over HTTPS."
                    ),
                    cwe="CWE-614",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        if not cookie.httponly:
            findings.append(
                Finding(
                    title=(
                        "Session Cookie Missing HttpOnly Attribute"
                    ),
                    severity="medium",
                    confidence="high",
                    target=target,
                    endpoint=target,
                    parameter=cookie.name,
                    description=(
                        "A session cookie is accessible "
                        "to client-side scripts because "
                        "the HttpOnly attribute is missing."
                    ),
                    evidence=(
                        f"Cookie: {cookie.name}; "
                        "HttpOnly: false"
                    ),
                    remediation=(
                        "Set the HttpOnly attribute on "
                        "session cookies when client-side "
                        "JavaScript does not require access."
                    ),
                    cwe="CWE-1004",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        if cookie.samesite is None:
            findings.append(
                Finding(
                    title=(
                        "Session Cookie Missing SameSite Attribute"
                    ),
                    severity="low",
                    confidence="high",
                    target=target,
                    endpoint=target,
                    parameter=cookie.name,
                    description=(
                        "A session cookie does not explicitly "
                        "define a SameSite policy."
                    ),
                    evidence=(
                        f"Cookie: {cookie.name}; "
                        "SameSite: missing"
                    ),
                    remediation=(
                        "Define an appropriate SameSite "
                        "attribute for the session cookie."
                    ),
                    cwe="CWE-1275",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        if (
            cookie.samesite is not None
            and cookie.samesite.lower() == "none"
            and not cookie.secure
        ):
            findings.append(
                Finding(
                    title=(
                        "SameSite=None Cookie Missing Secure Attribute"
                    ),
                    severity="medium",
                    confidence="high",
                    target=target,
                    endpoint=target,
                    parameter=cookie.name,
                    description=(
                        "A session cookie uses SameSite=None "
                        "without the Secure attribute."
                    ),
                    evidence=(
                        f"Cookie: {cookie.name}; "
                        "SameSite: None; "
                        "Secure: false"
                    ),
                    remediation=(
                        "Use the Secure attribute when "
                        "SameSite=None is required."
                    ),
                    cwe="CWE-614",
                    owasp="A05:2021 - Security Misconfiguration",
                )
            )

        return findings
