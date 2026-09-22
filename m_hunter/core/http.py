import time

import httpx


class HttpEngine:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

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
    ) -> httpx.Response:
        start_time = time.perf_counter()

        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = client.request(
                    method,
                    url,
                    headers=headers,
                    cookies=cookies,
                    params=params,
                    data=data,
                    json=json,
                )

            response_time = time.perf_counter() - start_time
            response.extensions["m_hunter_response_time"] = response_time

            content_length = len(response.content)
            response.extensions["m_hunter_content_length"] = content_length
            response.extensions["m_hunter_cookies"] = response.cookies
            response.extensions["m_hunter_final_url"] = str(response.url)

            return response

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

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs) -> httpx.Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> httpx.Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> httpx.Response:
        return self.request("OPTIONS", url, **kwargs)
