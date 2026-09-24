from dataclasses import dataclass, field
from fnmatch import fnmatch
from urllib.parse import urlparse

from m_hunter.recon.url import URL


@dataclass
class ScopeManager:
    base_url: URL
    allowed_hosts: set[str] | None = None
    excluded_paths: set[str] = field(default_factory=set)

    def __post_init__(self):
        if not isinstance(self.base_url, URL):
            raise TypeError(
                "base_url must be an instance of URL"
            )

        if self.allowed_hosts is None:
            self.allowed_hosts = {self.base_url.host}

        self.allowed_hosts = {
            host.strip().lower()
            for host in self.allowed_hosts
            if host.strip()
        }

        if not self.allowed_hosts:
            raise ValueError(
                "allowed_hosts must not be empty"
            )

        self.excluded_paths = {
            path.strip()
            for path in self.excluded_paths
            if path.strip()
        }

    def is_allowed(self, url: URL) -> bool:
        if not isinstance(url, URL):
            raise TypeError(
                "url must be an instance of URL"
            )

        parsed = urlparse(str(url))

        if parsed.hostname is None:
            return False

        host = parsed.hostname.lower()

        if host not in self.allowed_hosts:
            return False

        path = parsed.path or "/"

        for pattern in self.excluded_paths:
            if fnmatch(path, pattern):
                return False

        return True

    def add_allowed_host(self, host: str) -> None:
        host = host.strip().lower()

        if not host:
            raise ValueError(
                "host must not be empty"
            )

        self.allowed_hosts.add(host)

    def remove_allowed_host(self, host: str) -> bool:
        host = host.strip().lower()

        if host not in self.allowed_hosts:
            return False

        self.allowed_hosts.remove(host)

        if not self.allowed_hosts:
            raise ValueError(
                "allowed_hosts must not be empty"
            )

        return True

    def add_excluded_path(self, pattern: str) -> None:
        pattern = pattern.strip()

        if not pattern:
            raise ValueError(
                "pattern must not be empty"
            )

        self.excluded_paths.add(pattern)

    def remove_excluded_path(self, pattern: str) -> bool:
        pattern = pattern.strip()

        if pattern not in self.excluded_paths:
            return False

        self.excluded_paths.remove(pattern)
        return True


@dataclass
class CrawlQueue:
    max_urls: int = 1000
    _pending: list[URL] = field(default_factory=list)
    _queued: set[str] = field(default_factory=set)
    _visited: set[str] = field(default_factory=set)

    def __post_init__(self):
        if self.max_urls <= 0:
            raise ValueError(
                "max_urls must be greater than 0"
            )

    @staticmethod
    def _key(url: URL) -> str:
        return url.normalized

    def add(self, url: URL) -> bool:
        if not isinstance(url, URL):
            raise TypeError(
                "url must be an instance of URL"
            )

        key = self._key(url)

        if key in self._queued:
            return False

        if key in self._visited:
            return False

        if self.total_count >= self.max_urls:
            return False

        self._pending.append(url)
        self._queued.add(key)

        return True

    def add_many(self, urls: list[URL]) -> int:
        added = 0

        for url in urls:
            if self.add(url):
                added += 1

        return added

    def next(self) -> URL | None:
        if not self._pending:
            return None

        url = self._pending.pop(0)
        key = self._key(url)

        self._queued.discard(key)
        self._visited.add(key)

        return url

    def mark_visited(self, url: URL) -> bool:
        if not isinstance(url, URL):
            raise TypeError(
                "url must be an instance of URL"
            )

        key = self._key(url)

        if key in self._visited:
            return False

        self._queued.discard(key)
        self._pending = [
            item
            for item in self._pending
            if self._key(item) != key
        ]

        self._visited.add(key)

        return True

    def is_visited(self, url: URL) -> bool:
        if not isinstance(url, URL):
            raise TypeError(
                "url must be an instance of URL"
            )

        return self._key(url) in self._visited

    def is_pending(self, url: URL) -> bool:
        if not isinstance(url, URL):
            raise TypeError(
                "url must be an instance of URL"
            )

        return self._key(url) in self._queued

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def visited_count(self) -> int:
        return len(self._visited)

    @property
    def total_count(self) -> int:
        return (
            self.pending_count +
            self.visited_count
        )

    @property
    def is_empty(self) -> bool:
        return not self._pending

    @property
    def is_full(self) -> bool:
        return self.total_count >= self.max_urls

    def pending(self) -> list[URL]:
        return list(self._pending)

    def visited(self) -> list[str]:
        return list(self._visited)

    def clear(self) -> None:
        self._pending.clear()
        self._queued.clear()
        self._visited.clear()
