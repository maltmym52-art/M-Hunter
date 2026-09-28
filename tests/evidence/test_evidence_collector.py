import json

import pytest

from m_hunter.analyzers.context import AnalysisContext
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.evidence import EvidenceCollector, EvidenceLimits


def make_response():
    return HttpResponse(
        status_code=200,
        url="https://example.test/api?token=query-secret",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer response-secret",
            "Set-Cookie": "sid=session-secret; Path=/; HttpOnly",
        },
        content=b'{"message":"useful","password":"body-secret"}',
        cookies={"sid": "session-secret"},
        response_time=0.01,
        content_length=50,
    )


def test_capture_request_response_and_redacts_credentials():
    context = AnalysisContext(
        request=HttpRequest(
            "post",
            "https://example.test/api",
            headers={
                "Authorization": "Bearer request-secret",
                "X-Api-Key": "sk_test_01234567890123456789",
            },
            cookies={"sessionid": "cookie-secret", "theme": "dark"},
            params={"id": "7", "access_token": "query-secret"},
            body={"username": "alice", "password": "form-secret"},
        ),
        response=make_response(),
        metadata={"trace_id": "trace-1"},
    )
    record = EvidenceCollector().capture(
        context,
        analyzer="sqli",
        evidence="reflected input",
        description="response marker",
        parameter="id",
        input_value="' OR 1=1 --",
    )

    assert record.id
    assert record.url.startswith("https://example.test/api")
    assert record.method == "POST"
    assert record.status_code == 200
    assert record.timestamp.tzinfo is not None
    assert record.analyzer == "sqli"
    assert record.parameter == "id"
    assert record.input_value == "' OR 1=1 --"
    assert "Authorization" in record.request["headers"]
    assert record.request["headers"]["Authorization"] == "Bearer <REDACTED>"
    assert record.response["headers"]["Authorization"] == "Bearer <REDACTED>"
    assert record.response["headers"]["Set-Cookie"] == "sid=<REDACTED>; Path=/; HttpOnly"
    assert "session-secret" not in json.dumps(record.to_dict())
    assert "request-secret" not in json.dumps(record.to_dict())
    assert "form-secret" not in json.dumps(record.to_dict())
    assert "query-secret" not in json.dumps(record.to_dict())
    assert "useful" in record.body
    assert "body-secret" not in record.body
    assert record.raw.request["headers"]["Authorization"] == "Bearer request-secret"


def test_capture_empty_context_and_explicit_text_evidence():
    record = EvidenceCollector().capture(
        AnalysisContext(), evidence="a useful signal"
    )
    assert record.request is None
    assert record.response is None
    assert record.body is None
    assert record.sanitized.evidence == "a useful signal"
    assert record.to_dict()["evidence"] == "a useful signal"


def test_capture_truncates_fields_and_large_payloads_with_configured_limits():
    collector = EvidenceCollector(
        limits=EvidenceLimits(
            max_body_chars=24,
            max_field_chars=32,
            max_total_chars=256,
            max_headers=2,
            max_collection_items=4,
        )
    )
    record = collector.capture(
        AnalysisContext(
            request=HttpRequest(
                "GET",
                "https://example.test/" + "x" * 200,
                headers={f"X-{n}": "value" for n in range(8)},
            ),
            content="z" * 300,
        )
    )
    assert len(record.raw.body) <= 24
    assert len(record.body) <= 24
    assert "TRUNCATED" in record.body
    assert len(record.raw.request["headers"]) <= 2
    assert len(json.dumps(record.to_dict())) < 1000


def test_evidence_export_is_json_serializable_and_has_no_raw_section():
    record = EvidenceCollector().capture(
        AnalysisContext(metadata={"run_at": object()}),
        evidence="Authorization: Bearer top-secret",
    )
    exported = json.dumps(record.to_dict())
    assert "top-secret" not in exported
    assert '"raw"' not in exported


def test_redacts_jwt_api_keys_and_sensitive_form_fields():
    record = EvidenceCollector().capture(
        AnalysisContext(
            request=HttpRequest(
                "POST",
                "https://example.test/login?password=query-password",
                body={
                    "jwt": "eyJabcdefgh.ijklmnop.qrstuvwx",
                    "api_key": "sk_live_abcdefghijklmnop",
                    "username": "alice",
                    "password": "form-password",
                },
            ),
            content=(
                '{"jwt":"eyJabcdefgh.ijklmnop.qrstuvwx",'
                '"message":"operation completed"}'
            ),
        )
    )
    safe = json.dumps(record.to_dict())
    assert "eyJabcdefgh" not in safe
    assert "sk_live_abcdefghijklmnop" not in safe
    assert "query-password" not in safe
    assert "form-password" not in safe
    assert "operation completed" in safe


def test_limits_must_be_positive():
    with pytest.raises(ValueError):
        EvidenceLimits(max_total_chars=0)
