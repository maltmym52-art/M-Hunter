import time

import httpx

from m_hunter.config.settings import HttpSettings
from m_hunter.core.request import HttpRequest
from m_hunter.core.response import HttpResponse


class HttpEngine:
    def __init__(
        self,
        settings: HttpSettings | None = None,
    ):
        self.settings = settings or HttpSettings()

        self.timeout = self.settings.timeout
        self.follow_redirects = self.settings.follow_redirects
        self.user_agent = self.settings.user_agent

        self._client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            headers={
                "User-Agent": self.user_agent,
            },
        )

        self._closed = False

    def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        data=None,
        json=None,
    ) -> HttpResponse:
        if self._closed:
            raise RuntimeError("HttpEngine is closed")

        request_headers = dict(headers or {})

        if cookies:
            cookie_jar = httpx.Cookies(cookies)

            request = httpx.Request(
                method,
                url,
                headers=request_headers,
            )

            cookie_jar.set_cookie_header(request)

            request_headers = dict(request.headers)

        request_kwargs = {
            "headers": request_headers,
            "params": params,
        }

        if json is not None:
            request_kwargs["json"] = json
        elif data is not None:
            if isinstance(data, (str, bytes, bytearray)):
                request_kwargs["content"] = data
            else:
                request_kwargs["data"] = data

        start_time = time.perf_counter()

        try:
            response = self._client.request(
                method,
                url,
                **request_kwargs,
            )

            response_time = time.perf_counter() - start_time
            content = response.content

            headers, repeated_headers = (
                self._extract_response_headers(response)
            )

            return HttpResponse(
                status_code=response.status_code,
                url=str(response.url),
                headers=headers,
                content=content,
                cookies=dict(response.cookies),
                response_time=response_time,
                content_length=len(content),
                repeated_headers=repeated_headers,
            )

        except httpx.TimeoutException as exc:
            raise RuntimeError(
                f"HTTP request timed out: {url}"
            ) from exc

        except httpx.ConnectError as exc:
            raise RuntimeError(
                f"Failed to connect to: {url}"
            ) from exc

        except httpx.NetworkError as exc:
            raise RuntimeError(
                f"Network error while requesting: {url}"
            ) from exc

        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"HTTP error while requesting: {url}"
            ) from exc

    @staticmethod
    def _extract_response_headers(
        response: httpx.Response,
    ) -> tuple[dict[str, str], dict[str, list[str]]]:
        if not hasattr(response.headers, "multi_items"):
            return dict(response.headers), {}

        grouped: dict[str, list[str]] = {}

        for name, value in response.headers.multi_items():
            grouped.setdefault(name, []).append(value)

        headers = {
            name: values[0]
            for name, values in grouped.items()
        }

        repeated_headers = {
            name: values[1:]
            for name, values in grouped.items()
            if len(values) > 1
        }

        return headers, repeated_headers

    def send(self, request: HttpRequest) -> HttpResponse:
        if not isinstance(request, HttpRequest):
            raise TypeError("request must be an instance of HttpRequest")

        return self._send(
            request.method,
            request.url,
            headers=request.headers,
            cookies=request.cookies,
            params=request.params,
            data=request.body,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        data=None,
        json=None,
    ) -> HttpResponse:
        return self._send(
            method,
            url,
            headers=headers,
            cookies=cookies,
            params=params,
            data=data,
            json=json,
        )

    def close(self) -> None:
        if self._closed:
            return

        self._client.close()
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    @property
    def is_closed(self) -> bool:
        return self._closed

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
