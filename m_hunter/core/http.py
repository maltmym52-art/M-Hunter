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
        with httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            return client.request(
                method,
                url,
                headers=headers,
                cookies=cookies,
                params=params,
                data=data,
                json=json,
            )

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
