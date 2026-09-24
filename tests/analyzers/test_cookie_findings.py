from m_hunter.analyzers.cookie_findings import (
    CookieSecurityFindings,
)
from m_hunter.analyzers.set_cookie import (
    SetCookie,
)


def make_cookie(
    name="session",
    secure=True,
    httponly=True,
    samesite="Lax",
):
    return SetCookie(
        name=name,
        value="abc123",
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        path="/",
    )


def test_secure_session_cookie_has_no_findings():
    cookie = make_cookie()

    findings = CookieSecurityFindings().analyze(
        [cookie],
        "https://example.com",
    )

    assert findings == []


def test_missing_secure_creates_finding():
    cookie = make_cookie(
        secure=False,
    )

    findings = CookieSecurityFindings().analyze(
        [cookie],
        "https://example.com",
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Session Cookie Missing Secure Attribute"
    )
    assert findings[0].severity == "medium"
    assert findings[0].confidence == "high"
    assert findings[0].parameter == "session"
    assert findings[0].cwe == "CWE-614"


def test_missing_httponly_creates_finding():
    cookie = make_cookie(
        httponly=False,
    )

    findings = CookieSecurityFindings().analyze(
        [cookie],
        "https://example.com",
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Session Cookie Missing HttpOnly Attribute"
    )
    assert findings[0].severity == "medium"
    assert findings[0].cwe == "CWE-1004"


def test_missing_samesite_creates_finding():
    cookie = make_cookie(
        samesite=None,
    )

    findings = CookieSecurityFindings().analyze(
        [cookie],
        "https://example.com",
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Session Cookie Missing SameSite Attribute"
    )
    assert findings[0].severity == "low"
    assert findings[0].cwe == "CWE-1275"


def test_samesite_none_without_secure_creates_finding():
    cookie = make_cookie(
        secure=False,
        samesite="None",
    )

    findings = CookieSecurityFindings().analyze(
        [cookie],
        "https://example.com",
    )

    assert len(findings) == 2

    titles = {
        finding.title
        for finding in findings
    }

    assert (
        "Session Cookie Missing Secure Attribute"
        in titles
    )

    assert (
        "SameSite=None Cookie Missing Secure Attribute"
        in titles
    )


def test_samesite_none_with_secure_has_no_samesite_finding():
    cookie = make_cookie(
        secure=True,
        samesite="None",
    )

    findings = CookieSecurityFindings().analyze(
        [cookie],
        "https://example.com",
    )

    assert findings == []


def test_multiple_missing_attributes():
    cookie = make_cookie(
        secure=False,
        httponly=False,
        samesite=None,
    )

    findings = CookieSecurityFindings().analyze(
        [cookie],
        "https://example.com",
    )

    assert len(findings) == 3


def test_non_session_cookie_is_ignored():
    cookie = make_cookie(
        name="theme",
        secure=False,
        httponly=False,
        samesite=None,
    )

    findings = CookieSecurityFindings().analyze(
        [cookie],
        "https://example.com",
    )

    assert findings == []


def test_multiple_session_cookies_are_analyzed():
    cookies = [
        make_cookie(
            name="session",
            secure=False,
        ),
        make_cookie(
            name="JSESSIONID",
            httponly=False,
        ),
    ]

    findings = CookieSecurityFindings().analyze(
        cookies,
        "https://example.com",
    )

    assert len(findings) == 2

    assert findings[0].parameter == "session"
    assert findings[1].parameter == "JSESSIONID"


def test_finding_contains_evidence():
    cookie = make_cookie(
        secure=False,
    )

    findings = CookieSecurityFindings().analyze(
        [cookie],
        "https://example.com",
    )

    assert "session" in findings[0].evidence
    assert "Secure: false" in findings[0].evidence


def test_finding_contains_remediation():
    cookie = make_cookie(
        httponly=False,
    )

    findings = CookieSecurityFindings().analyze(
        [cookie],
        "https://example.com",
    )

    assert "HttpOnly" in findings[0].remediation


def test_target_is_preserved():
    cookie = make_cookie(
        secure=False,
    )

    target = "https://example.com/login"

    findings = CookieSecurityFindings().analyze(
        [cookie],
        target,
    )

    assert findings[0].target == target
    assert findings[0].endpoint == target


def test_empty_cookie_list():
    findings = CookieSecurityFindings().analyze(
        [],
        "https://example.com",
    )

    assert findings == []


def test_requires_list():
    try:
        CookieSecurityFindings().analyze(
            None,
            "https://example.com",
        )
    except TypeError:
        return

    assert False


def test_requires_string_target():
    try:
        CookieSecurityFindings().analyze(
            [],
            None,
        )
    except TypeError:
        return

    assert False


def test_empty_target_rejected():
    try:
        CookieSecurityFindings().analyze(
            [],
            "   ",
        )
    except ValueError:
        return

    assert False


def test_invalid_cookie_type_rejected():
    try:
        CookieSecurityFindings().analyze(
            ["session=abc"],
            "https://example.com",
        )
    except TypeError:
        return

    assert False
