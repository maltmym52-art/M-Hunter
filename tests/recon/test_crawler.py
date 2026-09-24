import pytest

from m_hunter.recon.crawler import Crawler
from m_hunter.recon.url import URL


def test_extracts_anchor_links():
    base = URL("https://example.com/")
    html = """
    <html>
        <a href="/login">Login</a>
        <a href="/about">About</a>
    </html>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 2
    assert [str(url) for url in result.urls] == [
        "https://example.com/login",
        "https://example.com/about",
    ]


def test_extracts_supported_resource_urls():
    base = URL("https://example.com/")
    html = """
    <a href="/page">page</a>
    <link href="/style.css">
    <script src="/app.js"></script>
    <img src="/image.png">
    <iframe src="/frame"></iframe>
    <form action="/submit"></form>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 6
    assert {url.path for url in result.urls} == {
        "/page",
        "/style.css",
        "/app.js",
        "/image.png",
        "/frame",
        "/submit",
    }


def test_resolves_relative_urls():
    base = URL("https://example.com/products/index.html")
    html = """
    <a href="details">details</a>
    <a href="../about">about</a>
    <a href="/login">login</a>
    """

    result = Crawler().crawl(base, html)

    assert {str(url) for url in result.urls} == {
        "https://example.com/products/details",
        "https://example.com/about",
        "https://example.com/login",
    }


def test_absolute_same_origin_url_is_kept():
    base = URL("https://example.com/")
    html = """
    <a href="https://example.com/account">account</a>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 1
    assert str(result.urls[0]) == "https://example.com/account"


def test_external_urls_are_filtered_by_default():
    base = URL("https://example.com/")
    html = """
    <a href="https://example.com/login">internal</a>
    <a href="https://other.com/">external</a>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 1
    assert str(result.urls[0]) == "https://example.com/login"


def test_external_urls_can_be_allowed():
    base = URL("https://example.com/")
    html = """
    <a href="https://example.com/login">internal</a>
    <a href="https://other.com/">external</a>
    """

    result = Crawler(same_origin=False).crawl(base, html)

    assert result.count == 2
    assert {
        str(url)
        for url in result.urls
    } == {
        "https://example.com/login",
        "https://other.com/",
    }


def test_duplicate_urls_are_removed():
    base = URL("https://example.com/")
    html = """
    <a href="/login">one</a>
    <a href="/login#section">two</a>
    <a href="https://example.com/login">three</a>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 1
    assert result.urls[0].normalized == "https://example.com/login"


def test_empty_and_missing_attributes_are_ignored():
    base = URL("https://example.com/")
    html = """
    <a>missing</a>
    <a href="">empty</a>
    <script></script>
    <img src="">
    <form action=""></form>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 0


def test_unsupported_tags_are_ignored():
    base = URL("https://example.com/")
    html = """
    <video src="/video.mp4"></video>
    <object data="/file.swf"></object>
    <div data-url="/hidden"></div>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 0


def test_query_parameters_are_preserved():
    base = URL("https://example.com/")
    html = """
    <a href="/search?q=test&page=2">search</a>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 1
    assert result.urls[0].parameters == {
        "q": "test",
        "page": "2",
    }


def test_fragment_is_not_used_for_deduplication():
    base = URL("https://example.com/")
    html = """
    <a href="/page#one">one</a>
    <a href="/page#two">two</a>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 1


def test_base_url_is_preserved():
    base = URL("https://example.com/app/")
    result = Crawler().crawl(base, "<a href='/login'>login</a>")

    assert result.base_url == base


def test_invalid_html_does_not_crash():
    base = URL("https://example.com/")
    html = """
    <html>
        <a href="/one">
        <script src="/app.js">
        <div>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 2


def test_base_url_type_is_required():
    with pytest.raises(TypeError):
        Crawler().crawl(
            "https://example.com/",
            "<a href='/test'>test</a>",
        )


def test_html_type_is_required():
    base = URL("https://example.com/")

    with pytest.raises(TypeError):
        Crawler().crawl(base, None)


def test_case_insensitive_html_tags():
    base = URL("https://example.com/")
    html = """
    <A HREF="/one">one</A>
    <SCRIPT SRC="/app.js"></SCRIPT>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 2


def test_protocol_relative_url():
    base = URL("https://example.com/")
    html = """
    <a href="//example.com/login">login</a>
    """

    result = Crawler().crawl(base, html)

    assert result.count == 1
    assert str(result.urls[0]) == "https://example.com/login"
