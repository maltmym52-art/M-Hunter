import pytest

from m_hunter.recon.scope import CrawlQueue, ScopeManager
from m_hunter.recon.url import URL


def test_default_scope_allows_base_host():
    scope = ScopeManager(
        URL("https://example.com/")
    )

    assert scope.is_allowed(
        URL("https://example.com/login")
    )


def test_default_scope_rejects_external_host():
    scope = ScopeManager(
        URL("https://example.com/")
    )

    assert not scope.is_allowed(
        URL("https://other.com/")
    )


def test_allowed_hosts_support_multiple_hosts():
    scope = ScopeManager(
        URL("https://example.com/"),
        allowed_hosts={
            "example.com",
            "api.example.com",
        },
    )

    assert scope.is_allowed(
        URL("https://example.com/")
    )
    assert scope.is_allowed(
        URL("https://api.example.com/v1")
    )
    assert not scope.is_allowed(
        URL("https://other.com/")
    )


def test_allowed_hosts_are_normalized():
    scope = ScopeManager(
        URL("https://example.com/"),
        allowed_hosts={
            " Example.COM ",
            "API.Example.COM",
        },
    )

    assert "example.com" in scope.allowed_hosts
    assert "api.example.com" in scope.allowed_hosts


def test_excluded_exact_path():
    scope = ScopeManager(
        URL("https://example.com/"),
        excluded_paths={"/logout"},
    )

    assert not scope.is_allowed(
        URL("https://example.com/logout")
    )

    assert scope.is_allowed(
        URL("https://example.com/login")
    )


def test_excluded_paths_support_wildcards():
    scope = ScopeManager(
        URL("https://example.com/"),
        excluded_paths={"/admin/*"},
    )

    assert not scope.is_allowed(
        URL("https://example.com/admin/login")
    )

    assert not scope.is_allowed(
        URL("https://example.com/admin/users")
    )

    assert scope.is_allowed(
        URL("https://example.com/account")
    )


def test_query_does_not_affect_excluded_path():
    scope = ScopeManager(
        URL("https://example.com/"),
        excluded_paths={"/logout"},
    )

    assert not scope.is_allowed(
        URL("https://example.com/logout?next=/")
    )


def test_add_allowed_host():
    scope = ScopeManager(
        URL("https://example.com/")
    )

    scope.add_allowed_host("api.example.com")

    assert scope.is_allowed(
        URL("https://api.example.com/")
    )


def test_remove_allowed_host():
    scope = ScopeManager(
        URL("https://example.com/"),
        allowed_hosts={
            "example.com",
            "api.example.com",
        },
    )

    assert scope.remove_allowed_host(
        "api.example.com"
    )

    assert not scope.is_allowed(
        URL("https://api.example.com/")
    )


def test_remove_missing_allowed_host():
    scope = ScopeManager(
        URL("https://example.com/")
    )

    assert not scope.remove_allowed_host(
        "missing.example.com"
    )


def test_cannot_remove_last_allowed_host():
    scope = ScopeManager(
        URL("https://example.com/")
    )

    with pytest.raises(ValueError):
        scope.remove_allowed_host(
            "example.com"
        )


def test_add_excluded_path():
    scope = ScopeManager(
        URL("https://example.com/")
    )

    scope.add_excluded_path("/private/*")

    assert not scope.is_allowed(
        URL("https://example.com/private/data")
    )


def test_remove_excluded_path():
    scope = ScopeManager(
        URL("https://example.com/"),
        excluded_paths={"/private/*"},
    )

    assert scope.remove_excluded_path(
        "/private/*"
    )

    assert scope.is_allowed(
        URL("https://example.com/private/data")
    )


def test_empty_allowed_hosts_rejected():
    with pytest.raises(ValueError):
        ScopeManager(
            URL("https://example.com/"),
            allowed_hosts=set(),
        )


def test_invalid_scope_base_url():
    with pytest.raises(TypeError):
        ScopeManager("https://example.com/")


def test_invalid_scope_url():
    scope = ScopeManager(
        URL("https://example.com/")
    )

    with pytest.raises(TypeError):
        scope.is_allowed(
            "https://example.com/"
        )


def test_empty_allowed_host_rejected():
    scope = ScopeManager(
        URL("https://example.com/")
    )

    with pytest.raises(ValueError):
        scope.add_allowed_host(" ")


def test_empty_excluded_path_rejected():
    scope = ScopeManager(
        URL("https://example.com/")
    )

    with pytest.raises(ValueError):
        scope.add_excluded_path(" ")


def test_queue_starts_empty():
    queue = CrawlQueue()

    assert queue.pending_count == 0
    assert queue.visited_count == 0
    assert queue.total_count == 0
    assert queue.is_empty
    assert not queue.is_full


def test_queue_adds_url():
    queue = CrawlQueue()

    url = URL("https://example.com/")

    assert queue.add(url)
    assert queue.pending_count == 1
    assert queue.is_pending(url)
    assert not queue.is_visited(url)


def test_queue_rejects_duplicate():
    queue = CrawlQueue()

    url = URL("https://example.com/")

    assert queue.add(url)
    assert not queue.add(url)

    assert queue.pending_count == 1


def test_queue_deduplicates_normalized_urls():
    queue = CrawlQueue()

    first = URL(
        "https://example.com/page#one"
    )
    second = URL(
        "https://example.com/page#two"
    )

    assert queue.add(first)
    assert not queue.add(second)


def test_queue_next_returns_fifo_order():
    queue = CrawlQueue()

    first = URL("https://example.com/one")
    second = URL("https://example.com/two")

    queue.add(first)
    queue.add(second)

    assert queue.next() == first
    assert queue.next() == second
    assert queue.next() is None


def test_next_marks_url_visited():
    queue = CrawlQueue()

    url = URL("https://example.com/")

    queue.add(url)

    assert queue.next() == url
    assert queue.is_visited(url)
    assert queue.visited_count == 1
    assert queue.pending_count == 0


def test_visited_url_cannot_be_readded():
    queue = CrawlQueue()

    url = URL("https://example.com/")

    queue.add(url)
    queue.next()

    assert not queue.add(url)


def test_mark_visited():
    queue = CrawlQueue()

    url = URL("https://example.com/")

    assert queue.mark_visited(url)
    assert queue.is_visited(url)
    assert not queue.is_pending(url)


def test_mark_visited_removes_pending_url():
    queue = CrawlQueue()

    url = URL("https://example.com/")

    queue.add(url)

    assert queue.mark_visited(url)
    assert queue.pending_count == 0
    assert queue.visited_count == 1


def test_mark_visited_duplicate_returns_false():
    queue = CrawlQueue()

    url = URL("https://example.com/")

    assert queue.mark_visited(url)
    assert not queue.mark_visited(url)


def test_queue_max_urls():
    queue = CrawlQueue(max_urls=2)

    first = URL("https://example.com/one")
    second = URL("https://example.com/two")
    third = URL("https://example.com/three")

    assert queue.add(first)
    assert queue.add(second)
    assert not queue.add(third)

    assert queue.is_full
    assert queue.total_count == 2


def test_queue_add_many():
    queue = CrawlQueue()

    urls = [
        URL("https://example.com/one"),
        URL("https://example.com/two"),
        URL("https://example.com/one"),
    ]

    assert queue.add_many(urls) == 2
    assert queue.pending_count == 2


def test_queue_pending_returns_copy():
    queue = CrawlQueue()

    url = URL("https://example.com/")

    queue.add(url)

    pending = queue.pending()
    pending.clear()

    assert queue.pending_count == 1


def test_queue_visited_returns_copy():
    queue = CrawlQueue()

    url = URL("https://example.com/")

    queue.add(url)
    queue.next()

    visited = queue.visited()
    visited.clear()

    assert queue.visited_count == 1


def test_queue_invalid_url_type():
    queue = CrawlQueue()

    with pytest.raises(TypeError):
        queue.add(
            "https://example.com/"
        )


def test_queue_invalid_next_behavior():
    queue = CrawlQueue()

    assert queue.next() is None


def test_queue_invalid_mark_visited_type():
    queue = CrawlQueue()

    with pytest.raises(TypeError):
        queue.mark_visited(
            "https://example.com/"
        )


def test_queue_invalid_is_visited_type():
    queue = CrawlQueue()

    with pytest.raises(TypeError):
        queue.is_visited(
            "https://example.com/"
        )


def test_queue_invalid_is_pending_type():
    queue = CrawlQueue()

    with pytest.raises(TypeError):
        queue.is_pending(
            "https://example.com/"
        )


def test_invalid_max_urls():
    with pytest.raises(ValueError):
        CrawlQueue(max_urls=0)


def test_queue_clear():
    queue = CrawlQueue()

    first = URL("https://example.com/one")
    second = URL("https://example.com/two")

    queue.add(first)
    queue.add(second)
    queue.next()

    queue.clear()

    assert queue.pending_count == 0
    assert queue.visited_count == 0
    assert queue.total_count == 0
    assert queue.is_empty
