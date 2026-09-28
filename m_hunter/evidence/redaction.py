"""Extensible secret and PII redaction for evidence snapshots."""

import json
import re
from collections.abc import Mapping
from typing import Any


REDACTED = "<REDACTED>"


class EvidenceRedactor:
    """Redact credential-like values while preserving useful evidence."""

    DEFAULT_SENSITIVE_NAMES = frozenset(
        {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "password",
            "passwd",
            "pwd",
            "secret",
            "client_secret",
            "client-secret",
            "api_key",
            "api-key",
            "apikey",
            "access_token",
            "access-token",
            "refresh_token",
            "refresh-token",
            "token",
            "session",
            "sessionid",
            "session_id",
            "sid",
        }
    )
    SENSITIVE_HEADER_NAMES = frozenset(
        {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "api-key",
            "x-auth-token",
        }
    )
    _BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
    _JWT = re.compile(
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
    )
    _SENSITIVE_ASSIGNMENT = re.compile(
        r"(?i)([\"']?(?:password|passwd|pwd|secret|client[_-]?secret|"
        r"api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|"
        r"session(?:id|_id)?|sid|cookie|token)[\"']?\s*[:=]\s*)"
        r"(\"[^\"]*\"|'[^']*'|[^&\s,;}}]+)"
    )
    _QUERY_VALUE = re.compile(
        r"(?i)([?&](?:password|passwd|pwd|secret|client[_-]?secret|"
        r"api[_-]?key|access[_-]?token|refresh[_-]?token|token|"
        r"session(?:id|_id)?|sid)=)[^&#\s]*"
    )
    _API_KEY = re.compile(
        r"(?i)\b(?:sk|pk|api)[_-][A-Za-z0-9_-]{16,}\b"
    )

    def __init__(
        self,
        *,
        sensitive_names: set[str] | None = None,
        sensitive_headers: set[str] | None = None,
        replacement: str = REDACTED,
    ) -> None:
        self.sensitive_names = self.DEFAULT_SENSITIVE_NAMES | frozenset(
            name.casefold() for name in (sensitive_names or set())
        )
        self.sensitive_headers = self.SENSITIVE_HEADER_NAMES | frozenset(
            name.casefold() for name in (sensitive_headers or set())
        )
        self.replacement = replacement

    def is_sensitive_name(self, name: str) -> bool:
        normalized = name.casefold().replace("-", "_")
        return normalized in {
            item.replace("-", "_") for item in self.sensitive_names
        } or any(
            marker in normalized
            for marker in ("password", "secret", "token", "api_key", "session")
        )

    def redact_text(self, value: str) -> str:
        """Redact common credentials in headers, URLs, forms, and body text."""
        value = self._BEARER.sub(f"Bearer {self.replacement}", value)
        value = self._JWT.sub(self.replacement, value)
        value = self._SENSITIVE_ASSIGNMENT.sub(
            lambda match: match.group(1) + self.replacement,
            value,
        )
        value = self._QUERY_VALUE.sub(
            lambda match: match.group(1) + self.replacement,
            value,
        )
        return self._API_KEY.sub(self.replacement, value)

    def redact_headers(self, headers: Mapping[str, Any]) -> dict[str, Any]:
        redacted: dict[str, Any] = {}
        for name, value in headers.items():
            normalized_name = str(name).casefold()
            if normalized_name in self.sensitive_headers:
                if normalized_name in {"cookie", "set-cookie"}:
                    redacted[name] = self._redact_cookie_header(str(value))
                elif normalized_name in {"authorization", "proxy-authorization"}:
                    scheme, separator, _credential = str(value).partition(" ")
                    redacted[name] = (
                        f"{scheme} {self.replacement}"
                        if separator and scheme.casefold() == "bearer"
                        else self.replacement
                    )
                else:
                    redacted[name] = self.replacement
            else:
                redacted[name] = self.redact_value(value)
        return redacted

    def redact_value(self, value: Any, *, key: str | None = None) -> Any:
        if key is not None and self.is_sensitive_name(key):
            return self.replacement
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, bytes):
            return self.redact_text(value.decode("utf-8", errors="replace"))
        if isinstance(value, Mapping):
            return {
                str(name): self.redact_value(item, key=str(name))
                for name, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self.redact_value(item) for item in value]
        return value

    def redact_cookies(self, cookies: Mapping[str, Any]) -> dict[str, str]:
        """Keep cookie names useful for analysis while hiding all values."""
        return {
            str(name): self.replacement
            for name in cookies
        }

    def redact_body(self, value: Any) -> Any:
        if isinstance(value, (dict, list)):
            return self.redact_value(value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (ValueError, TypeError):
                return self.redact_text(value)
            return json.dumps(
                self.redact_value(parsed),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        if isinstance(value, bytes):
            return self.redact_body(value.decode("utf-8", errors="replace"))
        return value

    def _redact_cookie_header(self, value: str) -> str:
        parts = []
        for item in value.split(";"):
            name, separator, _cookie_value = item.strip().partition("=")
            if not separator:
                parts.append(item.strip())
            elif name.casefold() in {"path", "domain", "expires", "max-age", "samesite"}:
                parts.append(f"{name}={_cookie_value.strip()}")
            else:
                parts.append(f"{name}={self.replacement}")
        return "; ".join(parts)
