import httpx


class HttpEngine:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def get(self, url: str) -> httpx.Response:
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            return client.get(url)
