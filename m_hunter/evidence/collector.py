"""Build bounded raw and sanitized evidence from analyzer context."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from m_hunter.analyzers.context import AnalysisContext
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.evidence.model import Evidence, EvidenceData
from m_hunter.evidence.redaction import EvidenceRedactor


TRUNCATION_MARKER = "...[TRUNCATED]"


@dataclass(frozen=True)
class EvidenceLimits:
    """Configurable limits applied to both raw and sanitized snapshots."""

    max_body_chars: int = 32_000
    max_field_chars: int = 8_000
    max_total_chars: int = 64_000
    max_headers: int = 128
    max_collection_items: int = 256

    def __post_init__(self) -> None:
        if min(
            self.max_body_chars,
            self.max_field_chars,
            self.max_total_chars,
            self.max_headers,
            self.max_collection_items,
        ) <= 0:
            raise ValueError("evidence limits must be greater than 0")


class EvidenceCollector:
    """Collect evidence and produce a safe reporting representation."""

    def __init__(
        self,
        *,
        redactor: EvidenceRedactor | None = None,
        limits: EvidenceLimits | None = None,
    ) -> None:
        self.redactor = redactor or EvidenceRedactor()
        self.limits = limits or EvidenceLimits()

    def capture(
        self,
        context: AnalysisContext,
        *,
        analyzer: str | None = None,
        source: str = "analysis",
        evidence: str = "",
        description: str = "",
        parameter: str | None = None,
        input_value: Any = None,
    ) -> Evidence:
        if not isinstance(context, AnalysisContext):
            raise TypeError("context must be an AnalysisContext")

        request = self._request_data(context.request)
        response = self._response_data(context.response)
        request_headers = (request or {}).get("headers", {})
        response_headers = (response or {}).get("headers", {})
        headers = {
            "request": request_headers,
            "response": response_headers,
        }
        url = (
            context.request_url
            or (request or {}).get("url")
            or (response or {}).get("url")
        )
        method = (request or {}).get("method")
        status_code = (response or {}).get("status_code")
        body = (response or {}).get("body")
        if body is None and context.content is not None:
            body = context.content

        timestamp = datetime.now(timezone.utc)
        raw = EvidenceData(
            request=request,
            response=response,
            url=url,
            method=method,
            status_code=status_code,
            headers=headers,
            body=self._as_text(body),
            parameter=parameter,
            input_value=input_value,
            analyzer=analyzer,
            source=source,
            timestamp=timestamp,
            description=description,
            context=dict(context.metadata),
            evidence=evidence,
        )
        bounded_raw = self._bound_snapshot(raw)
        sanitized = self._redact_snapshot(bounded_raw)
        sanitized = self._bound_snapshot(sanitized)
        return Evidence(raw=bounded_raw, sanitized=sanitized)

    @staticmethod
    def _as_text(value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            return value
        return str(value)

    def _request_data(self, request: HttpRequest | None) -> dict[str, Any] | None:
        if request is None:
            return None
        return {
            "method": request.method,
            "url": request.full_url,
            "headers": dict(
                list(request.headers.items())[: self.limits.max_headers]
            ),
            "cookies": dict(request.cookies),
            "parameters": dict(request.params),
            "body": request.body,
        }

    def _response_data(self, response: HttpResponse | None) -> dict[str, Any] | None:
        if response is None:
            return None
        return {
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(
                list(response.get_headers().items())[: self.limits.max_headers]
            ),
            "cookies": dict(response.cookies),
            "body": response.text,
        }

    def _redact_snapshot(self, data: EvidenceData) -> EvidenceData:
        request = self._redact_request(data.request)
        response = self._redact_response(data.response)
        header_map = {
            "request": self.redactor.redact_headers(
                data.headers.get("request", {})
            ),
            "response": self.redactor.redact_headers(
                data.headers.get("response", {})
            ),
        }
        parameter = data.parameter
        input_value = self.redactor.redact_value(
            data.input_value,
            key=parameter,
        )
        return EvidenceData(
            request=request,
            response=response,
            url=self.redactor.redact_text(data.url) if data.url else None,
            method=data.method,
            status_code=data.status_code,
            headers=header_map,
            body=self.redactor.redact_body(data.body),
            parameter=parameter,
            input_value=input_value,
            analyzer=data.analyzer,
            source=data.source,
            timestamp=data.timestamp,
            description=self.redactor.redact_text(data.description),
            context=self.redactor.redact_value(data.context),
            evidence=self.redactor.redact_text(data.evidence),
        )

    def _redact_request(self, request: Any) -> Any:
        if not isinstance(request, dict):
            return self.redactor.redact_value(request)
        return {
            **request,
            "url": self.redactor.redact_text(str(request.get("url", ""))),
            "headers": self.redactor.redact_headers(
                request.get("headers", {})
            ),
            "cookies": self.redactor.redact_cookies(
                request.get("cookies", {})
            ),
            "parameters": self.redactor.redact_value(
                request.get("parameters", {})
            ),
            "body": self.redactor.redact_body(request.get("body")),
        }

    def _redact_response(self, response: Any) -> Any:
        if not isinstance(response, dict):
            return self.redactor.redact_value(response)
        return {
            **response,
            "url": self.redactor.redact_text(str(response.get("url", ""))),
            "headers": self.redactor.redact_headers(
                response.get("headers", {})
            ),
            "cookies": self.redactor.redact_cookies(
                response.get("cookies", {})
            ),
            "body": self.redactor.redact_body(response.get("body")),
        }

    def _bound_snapshot(self, data: EvidenceData) -> EvidenceData:
        budget = [self.limits.max_total_chars]
        body = self._bound(data.body, budget, self.limits.max_body_chars)
        values = {
            "request": self._bound(data.request, budget),
            "response": self._bound(data.response, budget),
            "url": self._bound(data.url, budget),
            "method": self._bound(data.method, budget),
            "status_code": data.status_code,
            "headers": self._bound(data.headers, budget),
            "body": body,
            "parameter": self._bound(data.parameter, budget),
            "input_value": self._bound(data.input_value, budget),
            "analyzer": self._bound(data.analyzer, budget),
            "source": self._bound(data.source, budget),
            "timestamp": data.timestamp,
            "description": self._bound(data.description, budget),
            "context": self._bound(data.context, budget),
            "evidence": self._bound(data.evidence, budget),
        }
        return EvidenceData(**values)

    def _bound(
        self,
        value: Any,
        budget: list[int],
        max_chars: int | None = None,
    ) -> Any:
        if isinstance(value, str):
            limit = self.limits.max_field_chars
            if max_chars is not None:
                limit = min(limit, max_chars)
            limit = min(limit, budget[0])
            result = value
            if len(result) > limit:
                suffix = TRUNCATION_MARKER[:limit]
                result = result[: max(0, limit - len(suffix))] + suffix
            budget[0] = max(0, budget[0] - len(result))
            return result
        if isinstance(value, bytes):
            return self._bound(value.decode("utf-8", errors="replace"), budget, max_chars)
        if isinstance(value, dict):
            result = {}
            items = list(value.items())[: self.limits.max_collection_items]
            for key, item in items:
                if budget[0] <= 0:
                    break
                result[str(key)] = self._bound(item, budget)
            return result
        if isinstance(value, (list, tuple)):
            result = []
            for item in value[: self.limits.max_collection_items]:
                if budget[0] <= 0:
                    break
                result.append(self._bound(item, budget))
            return result
        return value
