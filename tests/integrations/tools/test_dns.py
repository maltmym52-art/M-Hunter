import pytest

from m_hunter.integrations.tools.dns import (
    DNSDiscoverySource,
    DNSResolver,
    StaticDNSResolver,
)


def test_dns_resolver_is_abstract():
    with pytest.raises(TypeError):
        DNSResolver()


def test_static_resolver_defaults_to_empty():
    resolver = StaticDNSResolver()

    assert resolver.resolve(
        "example.com",
        "A",
    ) == []


def test_static_resolver_returns_records():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "A",
            ): [
                "192.0.2.1",
                "192.0.2.2",
            ]
        }
    )

    assert resolver.resolve(
        "example.com",
        "A",
    ) == [
        "192.0.2.1",
        "192.0.2.2",
    ]


def test_static_resolver_is_case_insensitive_for_record_type():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "A",
            ): [
                "192.0.2.1",
            ]
        }
    )

    assert resolver.resolve(
        "example.com",
        "a",
    ) == [
        "192.0.2.1",
    ]


def test_static_resolver_returns_copy():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "A",
            ): [
                "192.0.2.1",
            ]
        }
    )

    result = resolver.resolve(
        "example.com",
        "A",
    )

    result.clear()

    assert resolver.resolve(
        "example.com",
        "A",
    ) == [
        "192.0.2.1",
    ]


def test_source_name():
    resolver = StaticDNSResolver()

    source = DNSDiscoverySource(
        resolver
    )

    assert source.name == "dns"


def test_resolver_is_required():
    with pytest.raises(
        TypeError,
        match="resolver must be an instance of DNSResolver",
    ):
        DNSDiscoverySource(
            object()
        )


def test_default_record_types():
    resolver = StaticDNSResolver()

    source = DNSDiscoverySource(
        resolver
    )

    assert source.record_types == (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "TXT",
    )


def test_custom_record_types_are_normalized():
    resolver = StaticDNSResolver()

    source = DNSDiscoverySource(
        resolver,
        record_types=(
            "a",
            "aaaa",
        ),
    )

    assert source.record_types == (
        "A",
        "AAAA",
    )


def test_empty_record_type_is_rejected():
    resolver = StaticDNSResolver()

    with pytest.raises(
        ValueError,
        match="record type must not be empty",
    ):
        DNSDiscoverySource(
            resolver,
            record_types=("A", ""),
        )


def test_empty_target_is_rejected():
    resolver = StaticDNSResolver()

    source = DNSDiscoverySource(
        resolver
    )

    with pytest.raises(
        ValueError,
        match="target must not be empty",
    ):
        source.discover("")


def test_whitespace_target_is_rejected():
    resolver = StaticDNSResolver()

    source = DNSDiscoverySource(
        resolver
    )

    with pytest.raises(
        ValueError,
        match="target must not be empty",
    ):
        source.discover("   ")


def test_a_record_becomes_ip_asset():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "A",
            ): [
                "192.0.2.1",
            ]
        }
    )

    source = DNSDiscoverySource(
        resolver,
        record_types=("A",),
    )

    assets = source.discover(
        "example.com"
    )

    assert len(assets) == 1
    assert assets[0].value == "192.0.2.1"
    assert assets[0].asset_type == "ip"
    assert assets[0].source == "dns"


def test_aaaa_record_becomes_ip_asset():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "AAAA",
            ): [
                "2001:db8::1",
            ]
        }
    )

    source = DNSDiscoverySource(
        resolver,
        record_types=("AAAA",),
    )

    assets = source.discover(
        "example.com"
    )

    assert assets[0].value == "2001:db8::1"
    assert assets[0].asset_type == "ip"


def test_cname_becomes_subdomain_asset():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "CNAME",
            ): [
                "target.example.net.",
            ]
        }
    )

    source = DNSDiscoverySource(
        resolver,
        record_types=("CNAME",),
    )

    assets = source.discover(
        "example.com"
    )

    assert assets[0].value == "target.example.net"
    assert assets[0].asset_type == "subdomain"


def test_mx_becomes_domain_asset():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "MX",
            ): [
                "mail.example.com.",
            ]
        }
    )

    source = DNSDiscoverySource(
        resolver,
        record_types=("MX",),
    )

    assets = source.discover(
        "example.com"
    )

    assert assets[0].value == "mail.example.com"
    assert assets[0].asset_type == "domain"


def test_txt_becomes_domain_asset():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "TXT",
            ): [
                "v=spf1 include:example.net",
            ]
        }
    )

    source = DNSDiscoverySource(
        resolver,
        record_types=("TXT",),
    )

    assets = source.discover(
        "example.com"
    )

    assert assets[0].asset_type == "domain"


def test_multiple_record_types_are_discovered():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "A",
            ): [
                "192.0.2.1",
            ],
            (
                "example.com",
                "AAAA",
            ): [
                "2001:db8::1",
            ],
            (
                "example.com",
                "CNAME",
            ): [
                "cdn.example.net.",
            ],
        }
    )

    source = DNSDiscoverySource(
        resolver,
        record_types=(
            "A",
            "AAAA",
            "CNAME",
        ),
    )

    assets = source.discover(
        "example.com"
    )

    assert [
        (
            asset.value,
            asset.asset_type,
        )
        for asset in assets
    ] == [
        (
            "192.0.2.1",
            "ip",
        ),
        (
            "2001:db8::1",
            "ip",
        ),
        (
            "cdn.example.net",
            "subdomain",
        ),
    ]


def test_empty_records_are_ignored():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "A",
            ): [
                "",
                "   ",
                "192.0.2.1",
            ]
        }
    )

    source = DNSDiscoverySource(
        resolver,
        record_types=("A",),
    )

    assets = source.discover(
        "example.com"
    )

    assert [
        asset.value
        for asset in assets
    ] == [
        "192.0.2.1",
    ]


def test_duplicate_records_are_removed():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "A",
            ): [
                "192.0.2.1",
                "192.0.2.1",
            ]
        }
    )

    source = DNSDiscoverySource(
        resolver,
        record_types=("A",),
    )

    assets = source.discover(
        "example.com"
    )

    assert len(assets) == 1


def test_same_value_with_different_asset_types_is_allowed():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "A",
            ): [
                "example.com",
            ],
            (
                "example.com",
                "CNAME",
            ): [
                "example.com",
            ],
        }
    )

    source = DNSDiscoverySource(
        resolver,
        record_types=(
            "A",
            "CNAME",
        ),
    )

    assets = source.discover(
        "example.com"
    )

    assert len(assets) == 2


def test_trailing_dots_are_removed():
    resolver = StaticDNSResolver(
        {
            (
                "example.com",
                "A",
            ): [
                "192.0.2.1.",
            ]
        }
    )

    source = DNSDiscoverySource(
        resolver,
        record_types=("A",),
    )

    assets = source.discover(
        "example.com"
    )

    assert assets[0].value == "192.0.2.1"


def test_discovery_queries_each_record_type():
    class RecordingResolver(DNSResolver):
        def __init__(self):
            self.calls = []

        def resolve(
            self,
            hostname,
            record_type="A",
        ):
            self.calls.append(
                (
                    hostname,
                    record_type,
                )
            )
            return []

    resolver = RecordingResolver()

    source = DNSDiscoverySource(
        resolver,
        record_types=(
            "A",
            "AAAA",
            "MX",
        ),
    )

    source.discover(
        "example.com"
    )

    assert resolver.calls == [
        (
            "example.com",
            "A",
        ),
        (
            "example.com",
            "AAAA",
        ),
        (
            "example.com",
            "MX",
        ),
    ]
