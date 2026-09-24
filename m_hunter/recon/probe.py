from dataclasses import dataclass

from m_hunter.core.http import HttpEngine
from m_hunter.core.response import HttpResponse
from m_hunter.recon.asset import Asset


PROBEABLE_ASSET_TYPES = {
    "domain",
    "subdomain",
    "url",
    "endpoint",
    "api",
}


@dataclass(frozen=True)
class ProbeResult:
    asset_id: str
    asset: Asset
    alive: bool
    status_code: int | None = None
    url: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    response_time: float | None = None
    server: str | None = None
    title: str | None = None
    redirect_url: str | None = None
    error: str | None = None


class HTTPProbe:
    """Probes web assets using the M-Hunter HTTP engine."""

    def __init__(
        self,
        http: HttpEngine | None = None,
        scheme: str = "https",
    ):
        if not scheme.strip():
            raise ValueError(
                "scheme must not be empty"
            )

        self.http = http or HttpEngine()
        self.scheme = scheme.rstrip(":/").lower()

    def probe(self, asset: Asset) -> ProbeResult:
        if not isinstance(asset, Asset):
            raise TypeError(
                "asset must be an instance of Asset"
            )

        if asset.asset_type not in PROBEABLE_ASSET_TYPES:
            return ProbeResult(
                asset_id=asset.id,
                asset=asset,
                alive=False,
                error=(
                    f"asset type is not probeable: "
                    f"{asset.asset_type}"
                ),
            )

        url = self._build_url(asset)

        try:
            response = self.http.get(url)

        except RuntimeError as exc:
            return ProbeResult(
                asset_id=asset.id,
                asset=asset,
                alive=False,
                url=url,
                error=str(exc),
            )

        return self._from_response(
            asset,
            response,
        )

    def _build_url(self, asset: Asset) -> str:
        value = asset.value.strip()

        if value.startswith(
            (
                "http://",
                "https://",
            )
        ):
            return value

        return f"{self.scheme}://{value}"

    def _from_response(
        self,
        asset: Asset,
        response: HttpResponse,
    ) -> ProbeResult:
        redirect_url = response.get_header(
            "location"
        )

        server = response.get_header(
            "server"
        )

        title = (
            self._extract_title(response.text)
            if response.is_html()
            else None
        )

        alive = True

        asset.alive = alive

        return ProbeResult(
            asset_id=asset.id,
            asset=asset,
            alive=alive,
            status_code=response.status_code,
            url=response.url,
            content_type=response.get_content_type(),
            content_length=response.content_length,
            response_time=response.response_time,
            server=server,
            title=title,
            redirect_url=redirect_url,
        )

    @staticmethod
    def _extract_title(content: str) -> str | None:
        lower = content.lower()

        start = lower.find("<title>")

        if start == -1:
            return None

        start += len("<title>")

        end = lower.find(
            "</title>",
            start,
        )

        if end == -1:
            return None

        title = content[start:end].strip()

        return title or None
