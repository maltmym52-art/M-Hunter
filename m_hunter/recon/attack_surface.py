from dataclasses import dataclass, field

from m_hunter.recon.asset import Asset
from m_hunter.recon.endpoint import Endpoint
from m_hunter.recon.javascript import JavaScriptURL
from m_hunter.recon.parameter import Parameter


@dataclass
class AttackSurface:
    assets: list[Asset] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    javascript_endpoints: list[JavaScriptURL] = field(
        default_factory=list
    )
    parameters: list[Parameter] = field(default_factory=list)

    def add_asset(self, asset: Asset) -> bool:
        if not isinstance(asset, Asset):
            raise TypeError(
                "asset must be an instance of Asset"
            )

        if any(
            existing == asset
            for existing in self.assets
        ):
            return False

        self.assets.append(asset)
        return True

    def add_endpoint(self, endpoint: Endpoint) -> bool:
        if not isinstance(endpoint, Endpoint):
            raise TypeError(
                "endpoint must be an instance of Endpoint"
            )

        if any(
            existing.key == endpoint.key
            for existing in self.endpoints
        ):
            return False

        self.endpoints.append(endpoint)
        return True

    def add_javascript_endpoint(
        self,
        endpoint: JavaScriptURL,
    ) -> bool:
        if not isinstance(
            endpoint,
            JavaScriptURL,
        ):
            raise TypeError(
                "endpoint must be an instance of "
                "JavaScriptURL"
            )

        if any(
            existing.url.normalized == endpoint.url.normalized
            for existing in self.javascript_endpoints
        ):
            return False

        self.javascript_endpoints.append(endpoint)
        return True

    def add_parameter(
        self,
        parameter: Parameter,
    ) -> bool:
        if not isinstance(parameter, Parameter):
            raise TypeError(
                "parameter must be an instance of Parameter"
            )

        if any(
            existing.key == parameter.key
            and existing.value == parameter.value
            for existing in self.parameters
        ):
            return False

        self.parameters.append(parameter)
        return True

    def add_assets(
        self,
        assets: list[Asset],
    ) -> int:
        added = 0

        for asset in assets:
            if self.add_asset(asset):
                added += 1

        return added

    def add_endpoints(
        self,
        endpoints: list[Endpoint],
    ) -> int:
        added = 0

        for endpoint in endpoints:
            if self.add_endpoint(endpoint):
                added += 1

        return added

    def add_javascript_endpoints(
        self,
        endpoints: list[JavaScriptURL],
    ) -> int:
        added = 0

        for endpoint in endpoints:
            if self.add_javascript_endpoint(endpoint):
                added += 1

        return added

    def add_parameters(
        self,
        parameters: list[Parameter],
    ) -> int:
        added = 0

        for parameter in parameters:
            if self.add_parameter(parameter):
                added += 1

        return added

    @property
    def asset_count(self) -> int:
        return len(self.assets)

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    @property
    def javascript_endpoint_count(self) -> int:
        return len(self.javascript_endpoints)

    @property
    def parameter_count(self) -> int:
        return len(self.parameters)

    @property
    def live_assets(self) -> list[Asset]:
        return [
            asset
            for asset in self.assets
            if asset.alive
        ]

    @property
    def live_asset_count(self) -> int:
        return len(self.live_assets)

    def all_urls(self) -> list[str]:
        urls: list[str] = []

        for endpoint in self.endpoints:
            value = endpoint.url.normalized

            if value not in urls:
                urls.append(value)

        for endpoint in self.javascript_endpoints:
            value = endpoint.url.normalized

            if value not in urls:
                urls.append(value)

        return urls

    @property
    def url_count(self) -> int:
        return len(self.all_urls())

    def clear(self) -> None:
        self.assets.clear()
        self.endpoints.clear()
        self.javascript_endpoints.clear()
        self.parameters.clear()
