from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl

from m_hunter.recon.scope import ScopeManager
from m_hunter.recon.url import URL


VALID_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
}


@dataclass(frozen=True)
class Endpoint:
    url: URL
    method: str = "GET"
    parameters: tuple[str, ...] = field(default_factory=tuple)
    source: str = "discovered"

    def __post_init__(self):
        if not isinstance(self.url, URL):
            raise TypeError(
                "url must be an instance of URL"
            )

        method = self.method.upper().strip()

        if method not in VALID_METHODS:
            raise ValueError(
                f"unsupported HTTP method: {method}"
            )

        object.__setattr__(self, "method", method)

        normalized_parameters = tuple(
            parameter.strip()
            for parameter in self.parameters
            if parameter.strip()
        )

        object.__setattr__(
            self,
            "parameters",
            normalized_parameters,
        )

        if not self.source.strip():
            raise ValueError(
                "source must not be empty"
            )

    @property
    def parameter_names(self) -> tuple[str, ...]:
        return self.parameters

    @property
    def key(self) -> tuple[str, str, tuple[str, ...]]:
        return (
            self.url.normalized,
            self.method,
            self.parameters,
        )


class _EndpointHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self.forms: list[tuple[str, str, list[str]]] = []

        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs):
        tag = tag.lower()
        attributes = dict(attrs)

        if tag == "a":
            href = attributes.get("href")

            if href:
                self.links.append(
                    (href.strip(), "link")
                )

        elif tag == "form":
            action = (
                attributes.get("action") or ""
            ).strip()

            method = (
                attributes.get("method") or "GET"
            ).strip().upper()

            self._current_form = {
                "action": action,
                "method": method,
                "parameters": [],
            }

        elif tag == "input":
            if self._current_form is None:
                return

            name = attributes.get("name")

            if name:
                name = name.strip()

                if name:
                    self._current_form[
                        "parameters"
                    ].append(name)

        elif tag == "textarea":
            if self._current_form is None:
                return

            name = attributes.get("name")

            if name:
                name = name.strip()

                if name:
                    self._current_form[
                        "parameters"
                    ].append(name)

        elif tag == "select":
            if self._current_form is None:
                return

            name = attributes.get("name")

            if name:
                name = name.strip()

                if name:
                    self._current_form[
                        "parameters"
                    ].append(name)

    def handle_endtag(self, tag: str):
        if tag.lower() != "form":
            return

        if self._current_form is None:
            return

        self.forms.append(
            (
                self._current_form["action"],
                self._current_form["method"],
                list(
                    self._current_form["parameters"]
                ),
            )
        )

        self._current_form = None

    def close(self):
        super().close()

        if self._current_form is not None:
            self.forms.append(
                (
                    self._current_form["action"],
                    self._current_form["method"],
                    list(
                        self._current_form["parameters"]
                    ),
                )
            )

            self._current_form = None


class EndpointDiscovery:
    def __init__(
        self,
        scope: ScopeManager,
    ):
        if not isinstance(scope, ScopeManager):
            raise TypeError(
                "scope must be an instance of ScopeManager"
            )

        self.scope = scope

    def discover(
        self,
        base_url: URL,
        html: str,
    ) -> list[Endpoint]:
        if not isinstance(base_url, URL):
            raise TypeError(
                "base_url must be an instance of URL"
            )

        if not isinstance(html, str):
            raise TypeError(
                "html must be a string"
            )

        parser = _EndpointHTMLParser()
        parser.feed(html)
        parser.close()

        endpoints: list[Endpoint] = []
        seen: set[
            tuple[str, str, tuple[str, ...]]
        ] = set()

        for raw_url, source in parser.links:
            endpoint = self._build_link_endpoint(
                base_url,
                raw_url,
                source,
            )

            if endpoint is None:
                continue

            if endpoint.key in seen:
                continue

            seen.add(endpoint.key)
            endpoints.append(endpoint)

        for (
            raw_action,
            method,
            parameters,
        ) in parser.forms:
            endpoint = self._build_form_endpoint(
                base_url,
                raw_action,
                method,
                parameters,
            )

            if endpoint is None:
                continue

            if endpoint.key in seen:
                continue

            seen.add(endpoint.key)
            endpoints.append(endpoint)

        return endpoints

    def _build_link_endpoint(
        self,
        base_url: URL,
        raw_url: str,
        source: str,
    ) -> Endpoint | None:
        try:
            url = base_url.resolve(raw_url)
        except ValueError:
            return None

        if not self.scope.is_allowed(url):
            return None

        parameter_names = tuple(
            name
            for name, _ in __import__(
                "urllib.parse",
                fromlist=["parse_qsl"],
            ).parse_qsl(
                url.query,
                keep_blank_values=True,
            )
        )

        return Endpoint(
            url=url,
            method="GET",
            parameters=parameter_names,
            source=source,
        )

    def _build_form_endpoint(
        self,
        base_url: URL,
        action: str,
        method: str,
        parameters: list[str],
    ) -> Endpoint | None:
        try:
            url = base_url.resolve(
                action or base_url.path
            )
        except ValueError:
            return None

        if not self.scope.is_allowed(url):
            return None

        if method not in VALID_METHODS:
            return None

        normalized_parameters = tuple(
            dict.fromkeys(
                parameter
                for parameter in parameters
                if parameter.strip()
            )
        )

        return Endpoint(
            url=url,
            method=method,
            parameters=normalized_parameters,
            source="form",
        )
