from m_hunter.analyzers.http_cookie_security import (
    HttpCookieSecurityAnalyzer,
)
from m_hunter.pipelines.http_cookie_security import (
    HttpCookieSecurityPipeline,
)


def test_pipeline_generates_findings():
    analysis = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        secure=False,
        httponly=False,
        samesite=None,
        domain=".example.com",
        path="/",
        max_age=40000000,
        duplicate_cookie=True,
    )

    pipeline = HttpCookieSecurityPipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
        endpoint="/login",
    )

    assert len(findings) == 7

    titles = {finding.title for finding in findings}

    assert "Cookie Missing Secure Attribute" in titles
    assert "Cookie Missing HttpOnly Attribute" in titles
    assert "Cookie Missing SameSite Attribute" in titles
    assert "Broad Cookie Domain Scope" in titles
    assert "Broad Cookie Path Scope" in titles
    assert "Long-Lived Cookie" in titles
    assert "Duplicate Cookie Name Detected" in titles


def test_pipeline_ignores_informational_indicators():
    analysis = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="session",
        secure=True,
        httponly=True,
        samesite="Strict",
        domain=None,
        path="/login",
        is_session_cookie=True,
    )

    pipeline = HttpCookieSecurityPipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
    )

    assert findings == []


def test_pipeline_handles_prefix_and_samesite():
    analysis = HttpCookieSecurityAnalyzer().analyze(
        cookie_name="__Secure-session",
        secure=False,
        httponly=True,
        samesite="None",
        domain="example.com",
        path="/",
    )

    pipeline = HttpCookieSecurityPipeline()

    findings = pipeline.run(
        analysis,
        "https://example.com",
        endpoint="/session",
    )

    assert len(findings) == 4

    titles = {finding.title for finding in findings}

    assert "Cookie Missing Secure Attribute" in titles
    assert "Cookie Uses SameSite=None" in titles
    assert "Broad Cookie Path Scope" in titles
    assert "Cookie Prefix Security Requirement Violation" in titles
