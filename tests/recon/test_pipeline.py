import pytest

from m_hunter.recon.asset import Asset
from m_hunter.recon.discovery import (
    DiscoveryEngine,
    DiscoverySource,
)
from m_hunter.recon.pipeline import (
    ReconPipeline,
    ReconResult,
)
from m_hunter.recon.probe import ProbeResult


class FakeDiscoverySource(DiscoverySource):
    name = "fake"

    def __init__(
        self,
        assets=None,
        error=None,
    ):
        self.assets = list(assets or [])
        self.error = error

    def discover(self, target):
        if self.error is not None:
            raise self.error

        return list(self.assets)


class FakeProbe:
    def __init__(
        self,
        results=None,
        errors=None,
    ):
        self.results = results or {}
        self.errors = errors or {}
        self.calls = []

    def probe(self, asset):
        self.calls.append(asset)

        if asset.value in self.errors:
            raise self.errors[asset.value]

        result = self.results.get(
            asset.value
        )

        if result is not None:
            if result.alive:
                asset.mark_alive()
            else:
                asset.mark_dead()

            return result

        return ProbeResult(
            asset_id=asset.id,
            asset=asset,
            alive=False,
            url=f"https://{asset.value}",
        )


def make_asset(
    value="example.com",
    asset_type="domain",
    alive=False,
):
    return Asset(
        value=value,
        asset_type=asset_type,
        alive=alive,
    )


def make_probe_result(
    asset,
    alive=True,
    status_code=200,
    url=None,
):
    return ProbeResult(
        asset_id=asset.id,
        asset=asset,
        alive=alive,
        status_code=status_code,
        url=url or f"https://{asset.value}",
    )


def make_pipeline(
    assets=None,
    probe=None,
):
    discovery = DiscoveryEngine(
        sources=[
            FakeDiscoverySource(
                assets=assets
            )
        ]
    )

    return ReconPipeline(
        discovery=discovery,
        probe=probe,
    )


def test_recon_result_defaults():
    result = ReconResult(
        target="example.com"
    )

    assert result.target == "example.com"
    assert result.discovered == []
    assert result.probes == []
    assert result.errors == []
    assert result.asset_count == 0
    assert result.live_count == 0
    assert result.probe_count == 0


def test_pipeline_requires_discovery():
    with pytest.raises(
        TypeError,
    ):
        ReconPipeline(
            discovery=None
        )


def test_pipeline_accepts_discovery():
    discovery = DiscoveryEngine()

    pipeline = ReconPipeline(
        discovery=discovery
    )

    assert pipeline.discovery is discovery


def test_pipeline_accepts_probe():
    discovery = DiscoveryEngine()
    probe = FakeProbe()

    pipeline = ReconPipeline(
        discovery=discovery,
        probe=probe,
    )

    assert pipeline.probe is probe


def test_empty_target_is_rejected():
    pipeline = make_pipeline()

    with pytest.raises(
        ValueError,
        match="target must not be empty",
    ):
        pipeline.run("")


def test_whitespace_target_is_rejected():
    pipeline = make_pipeline()

    with pytest.raises(
        ValueError,
        match="target must not be empty",
    ):
        pipeline.run("   ")


def test_target_is_trimmed():
    pipeline = make_pipeline()

    result = pipeline.run(
        "  example.com  ",
        probe_assets=False,
    )

    assert result.target == "example.com"


def test_discovery_only():
    assets = [
        make_asset(
            "example.com",
            "domain",
        ),
        make_asset(
            "api.example.com",
            "subdomain",
        ),
    ]

    pipeline = make_pipeline(
        assets=assets,
        probe=FakeProbe(),
    )

    result = pipeline.run(
        "example.com",
        probe_assets=False,
    )

    assert result.target == "example.com"
    assert result.discovered == assets
    assert result.asset_count == 2
    assert result.probes == []
    assert result.probe_count == 0


def test_discovery_and_probe():
    first = make_asset(
        "example.com",
        "domain",
    )

    second = make_asset(
        "api.example.com",
        "subdomain",
    )

    probe = FakeProbe(
        results={
            "example.com": make_probe_result(
                first,
                alive=True,
            ),
            "api.example.com": make_probe_result(
                second,
                alive=True,
            ),
        }
    )

    pipeline = make_pipeline(
        assets=[
            first,
            second,
        ],
        probe=probe,
    )

    result = pipeline.run(
        "example.com"
    )

    assert result.asset_count == 2
    assert result.probe_count == 2
    assert result.live_count == 2
    assert len(probe.calls) == 2


def test_live_assets_returns_only_alive_assets():
    first = make_asset(
        "example.com",
        "domain",
    )

    second = make_asset(
        "dead.example.com",
        "subdomain",
    )

    probe = FakeProbe(
        results={
            "example.com": make_probe_result(
                first,
                alive=True,
            ),
            "dead.example.com": make_probe_result(
                second,
                alive=False,
            ),
        }
    )

    pipeline = make_pipeline(
        assets=[
            first,
            second,
        ],
        probe=probe,
    )

    result = pipeline.run(
        "example.com"
    )

    assert result.live_assets == [first]
    assert result.live_count == 1


def test_probe_is_not_called_when_disabled():
    asset = make_asset()

    probe = FakeProbe()

    pipeline = make_pipeline(
        assets=[asset],
        probe=probe,
    )

    result = pipeline.run(
        "example.com",
        probe_assets=False,
    )

    assert result.probes == []
    assert probe.calls == []


def test_probe_is_not_called_when_not_configured():
    asset = make_asset()

    pipeline = make_pipeline(
        assets=[asset],
        probe=None,
    )

    result = pipeline.run(
        "example.com"
    )

    assert result.asset_count == 1
    assert result.probes == []
    assert result.errors == []


def test_multiple_discovery_sources_are_combined():
    first = make_asset(
        "example.com",
        "domain",
    )

    second = make_asset(
        "api.example.com",
        "subdomain",
    )

    discovery = DiscoveryEngine(
        sources=[
            FakeDiscoverySource(
                assets=[first]
            ),
            FakeDiscoverySource(
                assets=[second]
            ),
        ]
    )

    pipeline = ReconPipeline(
        discovery=discovery,
        probe_assets=False,
    ) if False else ReconPipeline(
        discovery=discovery
    )

    result = pipeline.run(
        "example.com",
        probe_assets=False,
    )

    assert result.discovered == [
        first,
        second,
    ]


def test_duplicate_discovery_results_are_removed():
    first = make_asset(
        "example.com",
        "domain",
    )

    duplicate = make_asset(
        "example.com",
        "domain",
    )

    discovery = DiscoveryEngine(
        sources=[
            FakeDiscoverySource(
                assets=[first]
            ),
            FakeDiscoverySource(
                assets=[duplicate]
            ),
        ]
    )

    pipeline = ReconPipeline(
        discovery=discovery
    )

    result = pipeline.run(
        "example.com",
        probe_assets=False,
    )

    assert result.asset_count == 1
    assert result.discovered == [first]


def test_probe_failure_does_not_stop_pipeline():
    first = make_asset(
        "example.com",
        "domain",
    )

    second = make_asset(
        "api.example.com",
        "subdomain",
    )

    probe = FakeProbe(
        results={
            "api.example.com": make_probe_result(
                second,
                alive=True,
            )
        },
        errors={
            "example.com": RuntimeError(
                "probe failed"
            )
        },
    )

    pipeline = make_pipeline(
        assets=[
            first,
            second,
        ],
        probe=probe,
    )

    result = pipeline.run(
        "example.com"
    )

    assert result.probe_count == 1
    assert result.live_count == 1
    assert len(result.errors) == 1
    assert "example.com" in result.errors[0]


def test_discovery_failure_returns_error():
    discovery = DiscoveryEngine(
        sources=[
            FakeDiscoverySource(
                error=RuntimeError(
                    "discovery failed"
                )
            )
        ]
    )

    pipeline = ReconPipeline(
        discovery=discovery
    )

    result = pipeline.run(
        "example.com"
    )

    assert result.discovered == []
    assert result.probes == []
    assert len(result.errors) == 1
    assert "discovery failed" in result.errors[0]


def test_discovery_failure_does_not_call_probe():
    discovery = DiscoveryEngine(
        sources=[
            FakeDiscoverySource(
                error=RuntimeError(
                    "discovery failed"
                )
            )
        ]
    )

    probe = FakeProbe()

    pipeline = ReconPipeline(
        discovery=discovery,
        probe=probe,
    )

    result = pipeline.run(
        "example.com"
    )

    assert result.errors
    assert probe.calls == []


def test_probe_results_are_preserved():
    asset = make_asset()

    expected = make_probe_result(
        asset,
        alive=True,
        status_code=200,
    )

    probe = FakeProbe(
        results={
            asset.value: expected
        }
    )

    pipeline = make_pipeline(
        assets=[asset],
        probe=probe,
    )

    result = pipeline.run(
        "example.com"
    )

    assert result.probes == [expected]
    assert result.probes[0].status_code == 200


def test_pipeline_uses_discovery_inventory():
    asset = make_asset()

    discovery = DiscoveryEngine(
        sources=[
            FakeDiscoverySource(
                assets=[asset]
            )
        ]
    )

    pipeline = ReconPipeline(
        discovery=discovery
    )

    result = pipeline.run(
        "example.com",
        probe_assets=False,
    )

    assert discovery.inventory.count() == 1
    assert result.discovered == [
        asset
    ]


def test_probe_calls_follow_discovery_order():
    first = make_asset(
        "one.example.com",
        "subdomain",
    )

    second = make_asset(
        "two.example.com",
        "subdomain",
    )

    probe = FakeProbe()

    pipeline = make_pipeline(
        assets=[
            first,
            second,
        ],
        probe=probe,
    )

    pipeline.run(
        "example.com"
    )

    assert probe.calls == [
        first,
        second,
    ]
