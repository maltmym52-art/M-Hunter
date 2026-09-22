import time

import httpx

from m_hunter.config.settings import HttpSettings
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
        if self._closed:
            raise RuntimeError("HttpEngine is closed")

        start_time = time.perf_counter()

        try:
            response = self._client.request(
                method,
                url,
                headers=headers,
                cookies=cookies,
                params=params,
                data=data,
                json=json,
            )

            response_time = time.perf_counter() - start_time
            content = response.content

            return HttpResponse(
                status_code=response.status_code,
                url=str(response.url),
                headers=dict(response.headers),
                content=content,
                cookies=dict(response.cookies),
                response_time=response_time,
                content_length=len(content),
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
