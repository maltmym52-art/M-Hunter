from dataclasses import dataclass, field
from html.parser import HTMLParser

from m_hunter.recon.url import URL


CRAWLABLE_TAGS = {
    "a": "href",
    "link": "href",
    "script": "src",
    "img": "src",
    "iframe": "src",
    "form": "action",
}


@dataclass
class CrawlResult:
    base_url: URL
    urls: list[URL] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.urls)


class _HTMLURLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        attribute = CRAWLABLE_TAGS.get(tag.lower())
        if attribute is None:
            return

        attributes = dict(attrs)
        value = attributes.get(attribute)

        if value:
            value = value.strip()
            if value:
                self.urls.append(value)


class Crawler:
    def __init__(self, *, same_origin: bool = True):
        self.same_origin = same_origin

    def crawl(self, base_url: URL, html: str) -> CrawlResult:
        if not isinstance(base_url, URL):
            raise TypeError(
                "base_url must be an instance of URL"
            )

        if not isinstance(html, str):
            raise TypeError("html must be a string")

        parser = _HTMLURLParser()
        parser.feed(html)
        parser.close()

        discovered: list[URL] = []
        seen: set[str] = set()

        for raw_url in parser.urls:
            try:
                url = base_url.resolve(raw_url)
            except ValueError:
                continue

            if self.same_origin and not base_url.is_same_origin(url):
                continue

            normalized = url.normalized

            if normalized in seen:
                continue

            seen.add(normalized)
            discovered.append(url)

        return CrawlResult(
            base_url=base_url,
            urls=discovered,
        )
