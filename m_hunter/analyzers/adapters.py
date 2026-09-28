"""Adapters for running legacy analyzers through the unified API."""

from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
import inspect
from typing import Any

from m_hunter.analyzers.base import BaseAnalyzer
from m_hunter.analyzers.capabilities import AnalyzerCapabilities
from m_hunter.analyzers.context import AnalysisContext
from m_hunter.analyzers.result import AnalysisResult
from m_hunter.core.response import HttpResponse


LegacyInvocation = Callable[[Any, AnalysisContext], Any]


class LegacyAnalyzerAdapter(BaseAnalyzer):
    """Expose an existing analyzer through ``BaseAnalyzer.run``.

    ``invoke`` maps a context to the legacy analyzer's existing call shape.
    If omitted, the wrapped analyzer is called with ``context.response``.
    The wrapped object's ``analyze`` method and public API are not modified.
    """

    def __init__(
        self,
        analyzer: Any,
        invoke: LegacyInvocation | None = None,
        *,
        name: str | None = None,
        capabilities: AnalyzerCapabilities | None = None,
    ) -> None:
        legacy_analyze = getattr(analyzer, "analyze", None)
        if not callable(legacy_analyze):
            raise TypeError("analyzer must provide a callable analyze method")

        analyzer_name = name or getattr(analyzer, "name", None)
        if analyzer_name is None:
            analyzer_name = analyzer.__class__.__module__.rsplit(".", 1)[-1]
        if not isinstance(analyzer_name, str) or not analyzer_name.strip():
            raise ValueError("analyzer must provide a non-empty name")

        self.analyzer = analyzer
        self.name = analyzer_name
        self.description = getattr(analyzer, "description", "Legacy analyzer")
        self._capabilities = capabilities or self._infer_capabilities(analyzer)
        self._invoke = invoke or self._invoke_from_context

    @property
    def capabilities(self) -> AnalyzerCapabilities:
        """Capabilities inferred from the wrapped legacy call contract."""
        return self._capabilities

    @staticmethod
    def _legacy_name(analyzer: Any) -> str:
        return getattr(
            analyzer,
            "name",
            analyzer.__class__.__module__.rsplit(".", 1)[-1],
        )

    @staticmethod
    def _infer_capabilities(analyzer: Any) -> AnalyzerCapabilities:
        """Infer passive context requirements from a legacy method signature."""
        signature = inspect.signature(analyzer.analyze)
        names = {parameter.name for parameter in signature.parameters.values()}
        required_names = {
            parameter.name for parameter in signature.parameters.values()
            if parameter.default is inspect.Parameter.empty
            and parameter.kind not in {inspect.Parameter.VAR_POSITIONAL,
                                       inspect.Parameter.VAR_KEYWORD}
        }
        response_backed = {"response", "headers", "cookies", "cookie_name",
                 "cookie_count", "duplicate_cookie", "multiple_cache_control", "multiple_security_header", "cache_control", "vary",
                 "pragma", "expires", "age", "surrogate_control", "secure", "httponly",
                 "samesite", "domain", "path", "max_age", "expires_seconds",
                 "is_session_cookie", "debug",
                 "stack_trace", "exception_details", "internal_path", "internal_ip",
                 "directory_listing", "server", "x_powered_by", "x_content_type_options",
                 "x_xss_protection", "expect_ct", "x_permitted_cross_domain_policies",
                 "clear_site_data"}
        return AnalyzerCapabilities(
            mode="passive", requires_authorization=False,
            requires_request="request" in required_names,
            requires_response=bool(names & response_backed),
            requires_context=bool(required_names - response_backed - {"request", "request_url", "target"}),
            description=getattr(analyzer, "description", "Legacy analyzer"),
        )

    @staticmethod
    def _invoke_from_context(
        analyzer: Any,
        context: AnalysisContext,
    ) -> Any:
        signature = inspect.signature(analyzer.analyze)
        positional = []
        keywords = {}
        for parameter in signature.parameters.values():
            if parameter.kind in {inspect.Parameter.VAR_POSITIONAL,
                                  inspect.Parameter.VAR_KEYWORD}:
                continue
            found, value = LegacyAnalyzerAdapter._context_value(parameter.name, context)
            if not found:
                if (parameter.name == "cookie_name" and context.response is not None
                        and not context.response.get_headers_all("set-cookie")):
                    # No cookie in the response means this check has no input;
                    # represent an empty analysis rather than a false positive.
                    from m_hunter.analyzers.http_cookie_security import CookieSecurityAnalysis
                    return CookieSecurityAnalysis(())
                if parameter.default is inspect.Parameter.empty:
                    if parameter.name == "response":
                        raise ValueError(
                            f"Analyzer {LegacyAnalyzerAdapter._legacy_name(analyzer)!r} "
                            "requires an HTTP response"
                        )
                    raise ValueError(
                        f"Analyzer {LegacyAnalyzerAdapter._legacy_name(analyzer)!r} "
                        f"requires context option {parameter.name!r}"
                    )
                continue
            if parameter.kind == inspect.Parameter.POSITIONAL_ONLY:
                positional.append(value)
            else:
                keywords[parameter.name] = value
        return analyzer.analyze(*positional, **keywords)

    @staticmethod
    def _context_value(name: str, context: AnalysisContext) -> tuple[bool, Any]:
        if name in context.options:
            return True, context.options[name]
        response = context.response
        request = context.request
        cookie_info = LegacyAnalyzerAdapter._cookie_attributes(response)
        if name in cookie_info:
            return True, cookie_info[name]
        if name == "response":
            return (response is not None, response)
        if name in {"content", "body"}:
            value = context.content if context.content is not None else (
                response.text if response is not None else None
            )
            return (value is not None, value)
        if name == "request":
            return (request is not None, request)
        if name in {"request_url", "url"}:
            value = context.request_url or (request.full_url if request else None) or (
                response.url if response else None
            )
            return (value is not None, value)
        if name == "target":
            return (context.target is not None, context.target)
        if name == "headers":
            value = response.get_headers() if response else None
            return (value is not None, value)
        if name == "cookies":
            value = response.cookies if response else None
            return (value is not None, value)
        if name == "cookie_name" and response and response.cookies:
            return True, next(iter(response.cookies))
        if name == "cookie_count" and response:
            return True, len(response.cookies)
        if name == "duplicate_cookie":
            return True, False
        if name == "multiple_cache_control" and response:
            return True, len(response.get_headers_all("cache-control")) > 1
        if name == "multiple_security_header" and response:
            names = ("x-content-type-options", "x-xss-protection", "expect-ct",
                     "x-permitted-cross-domain-policies", "clear-site-data")
            return True, any(len(response.get_headers_all(header)) > 1 for header in names)
        if name in {"cache_control", "pragma", "expires", "age", "vary",
                    "surrogate_control", "server", "x_powered_by",
                    "x_content_type_options", "x_xss_protection", "expect_ct",
                    "x_permitted_cross_domain_policies", "clear_site_data"} and response:
            header = name.replace("_", "-")
            values = response.get_headers_all(header)
            return (bool(values), ", ".join(values) if values else None)
        return False, None

    @staticmethod
    def _cookie_attributes(response: Any) -> dict[str, Any]:
        """Extract only cookie configuration; never return cookie values."""
        if response is None:
            return {}
        parsed: list[tuple[str, Any]] = []
        for header in response.get_headers_all("set-cookie"):
            cookie = SimpleCookie()
            try:
                cookie.load(header)
            except Exception:
                continue
            parsed.extend(cookie.items())
        if not parsed:
            return {}
        counts: dict[str, int] = {}
        for name, _morsel in parsed:
            counts[name] = counts.get(name, 0) + 1
        name, morsel = parsed[0]
        raw_max_age = morsel["max-age"]
        try:
            max_age = int(raw_max_age) if raw_max_age else None
        except ValueError:
            max_age = None
        expires = None
        if morsel["expires"]:
            try:
                expires = max(0, int((parsedate_to_datetime(morsel["expires"]) -
                                      datetime.now(timezone.utc)).total_seconds()))
            except (TypeError, ValueError, OverflowError):
                expires = None
        return {
            "cookie_name": name,
            "secure": bool(morsel["secure"]),
            "httponly": bool(morsel["httponly"]),
            "samesite": morsel["samesite"] or None,
            "domain": morsel["domain"] or None,
            "path": morsel["path"] or None,
            "max_age": max_age,
            "expires_seconds": expires,
            "is_session_cookie": max_age is None and not morsel["expires"],
            "duplicate_cookie": counts.get(name, 0) > 1,
            "cookie_count": len(parsed),
        }

    @classmethod
    def for_content(
        cls,
        analyzer: Any,
        *,
        content_getter: Callable[[AnalysisContext], str | bytes | None] | None = None,
    ) -> "LegacyAnalyzerAdapter":
        """Adapt analyzers whose legacy method accepts text or bytes content."""

        def invoke(legacy: Any, context: AnalysisContext) -> Any:
            content = (
                content_getter(context)
                if content_getter is not None
                else context.content
            )
            if content is None:
                raise ValueError(
                    f"Analyzer {LegacyAnalyzerAdapter._legacy_name(legacy)!r} requires content"
                )
            return legacy.analyze(content)

        return cls(
            analyzer,
            invoke,
            capabilities=AnalyzerCapabilities(
                mode="passive", requires_context=True,
                description=getattr(analyzer, "description", "Legacy content analyzer"),
            ),
        )

    def analyze(self, response: HttpResponse) -> Any:
        """Preserve response-based use for callers of the legacy API."""
        return self.run(AnalysisContext(response=response)).data

    def run(self, context: AnalysisContext) -> AnalysisResult:
        if not isinstance(context, AnalysisContext):
            raise TypeError("context must be an AnalysisContext")

        data = self._invoke(self.analyzer, context)
        if isinstance(data, AnalysisResult):
            return AnalysisResult(
                analyzer_name=self.name,
                data=data.data,
                status=data.status,
                errors=list(data.errors),
                metadata=data.metadata,
            )

        return AnalysisResult(
            analyzer_name=self.name,
            data=data,
        )
