"""Authorization and scope boundary for all application-owned HTTP activity."""

from urllib.parse import urlparse

from m_hunter.application.models import AuthorizationGrant
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse
from m_hunter.integrations.tools.runner import ToolRunner
from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL


class ScopeViolation(PermissionError):
    """Raised when an active operation is unauthorized or out of scope."""


class ScopedHttpEngine:
    """Guard an injected HTTP client with explicit grant and scope checks."""

    def __init__(
        self,
        http_engine: object,
        scope_manager: ScopeManager,
        authorization: AuthorizationGrant,
        *,
        active_enabled: bool,
    ) -> None:
        self._http = http_engine
        self.scope_manager = scope_manager
        self.authorization = authorization
        self.active_enabled = active_enabled
        self.request_count = 0
        self.request_log: list[HttpRequest] = []
        self.response_log: list[tuple[str, HttpResponse]] = []

    def _check(self, url: str) -> None:
        if not self.active_enabled:
            raise ScopeViolation("active testing is disabled for this scan")
        if not self.authorization.authorized:
            raise ScopeViolation("explicit authorization is required for active testing")
        try:
            scoped_url = URL(url)
        except (TypeError, ValueError) as exc:
            raise ScopeViolation(f"invalid active request URL: {url}") from exc
        if not self.scope_manager.is_allowed(scoped_url):
            raise ScopeViolation(f"active request is outside scope: {url}")

    def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        self._check(url)
        kwargs["follow_redirects"] = False
        self.request_count += 1
        outbound = HttpRequest(
            method=method,
            url=url,
            headers=dict(kwargs.get("headers") or {}),
            cookies=dict(kwargs.get("cookies") or {}),
            params=dict(kwargs.get("params") or {}),
            body=kwargs.get("data", kwargs.get("json")),
        )
        self.request_log.append(outbound)
        response = self._http.request(method, url, **kwargs)
        self.response_log.append((response.url or outbound.full_url, response))
        return response

    def send(self, request: HttpRequest) -> HttpResponse:
        self._check(request.full_url)
        return self.request(
            request.method,
            request.url,
            headers=request.headers,
            cookies=request.cookies,
            params=request.params,
            data=request.body,
        )

    def get(self, url: str, **kwargs) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> HttpResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> HttpResponse:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs) -> HttpResponse:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs) -> HttpResponse:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> HttpResponse:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> HttpResponse:
        return self.request("OPTIONS", url, **kwargs)


class ScopedToolRunner:
    """Run an injected tool only after authorization and target-scope checks."""

    def __init__(
        self,
        runner: ToolRunner,
        scope_manager: ScopeManager,
        authorization: AuthorizationGrant,
    ) -> None:
        self._runner = runner
        self.scope_manager = scope_manager
        self.authorization = authorization

    def is_available(self, executable: str) -> bool:
        return self._runner.is_available(executable)

    def run_scoped(
        self,
        target: str,
        command: list[str] | tuple[str, ...],
        **kwargs,
    ):
        if not self.authorization.authorized:
            raise ScopeViolation("explicit authorization is required for active tools")
        if not is_in_scope(self.scope_manager, target):
            raise ScopeViolation(f"tool target is outside scope: {target}")
        return self._runner.run(command, **kwargs)


def is_in_scope(scope_manager: ScopeManager, url: str) -> bool:
    """Return false for malformed URLs without allowing scope-check bypass."""
    try:
        return scope_manager.is_allowed(URL(url))
    except (TypeError, ValueError):
        return False


def asset_url(value: str, target: str) -> str:
    """Build an HTTP URL for a discovered hostname or preserve a discovered URL."""
    if value.startswith(("http://", "https://")):
        return value
    scheme = urlparse(target).scheme or "https"
    return f"{scheme}://{value}"
