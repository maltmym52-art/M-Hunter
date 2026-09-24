from dataclasses import dataclass, field
from urllib.parse import parse_qsl

from m_hunter.recon.endpoint import Endpoint


VALID_SOURCES = {
    "query",
    "form",
    "json",
    "path",
    "header",
    "cookie",
}


@dataclass(frozen=True)
class Parameter:
    name: str
    source: str
    value: str | None = None
    location: str | None = None

    def __post_init__(self):
        name = self.name.strip()
        source = self.source.strip().lower()

        if not name:
            raise ValueError("parameter name must not be empty")

        if source not in VALID_SOURCES:
            raise ValueError(
                f"unsupported parameter source: {source}"
            )

        if self.location is not None:
            location = self.location.strip()
            object.__setattr__(self, "location", location)

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "source", source)

    @property
    def key(self) -> tuple[str, str, str | None]:
        return (
            self.name,
            self.source,
            self.location,
        )


@dataclass
class ParameterInventory:
    parameters: list[Parameter] = field(default_factory=list)

    def add(self, parameter: Parameter) -> bool:
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

    def add_many(
        self,
        parameters: list[Parameter],
    ) -> int:
        added = 0

        for parameter in parameters:
            if self.add(parameter):
                added += 1

        return added

    def by_source(
        self,
        source: str,
    ) -> list[Parameter]:
        source = source.strip().lower()

        return [
            parameter
            for parameter in self.parameters
            if parameter.source == source
        ]

    def names(self) -> list[str]:
        return [
            parameter.name
            for parameter in self.parameters
        ]

    def count(self) -> int:
        return len(self.parameters)

    def clear(self) -> None:
        self.parameters.clear()


class ParameterDiscovery:
    def discover_endpoint(
        self,
        endpoint: Endpoint,
    ) -> ParameterInventory:
        if not isinstance(endpoint, Endpoint):
            raise TypeError(
                "endpoint must be an instance of Endpoint"
            )

        inventory = ParameterInventory()

        for name, value in parse_qsl(
            endpoint.url.query,
            keep_blank_values=True,
        ):
            inventory.add(
                Parameter(
                    name=name,
                    source="query",
                    value=value,
                    location=endpoint.url.path,
                )
            )

        for name in endpoint.parameters:
            source = (
                "form"
                if endpoint.source == "form"
                else "query"
            )

            parameter = Parameter(
                name=name,
                source=source,
                location=endpoint.url.path,
            )

            if not any(
                existing.key == parameter.key
                for existing in inventory.parameters
            ):
                inventory.add(parameter)

        return inventory

    def discover_query(
        self,
        url: str,
    ) -> ParameterInventory:
        if not isinstance(url, str):
            raise TypeError("url must be a string")

        url = url.strip()

        if not url:
            raise ValueError("url must not be empty")

        inventory = ParameterInventory()

        query = url.split("?", 1)[1] if "?" in url else ""

        for name, value in parse_qsl(
            query.split("#", 1)[0],
            keep_blank_values=True,
        ):
            inventory.add(
                Parameter(
                    name=name,
                    source="query",
                    value=value,
                )
            )

        return inventory

    def discover_form(
        self,
        fields: dict[str, str | None],
        *,
        location: str | None = None,
    ) -> ParameterInventory:
        if not isinstance(fields, dict):
            raise TypeError(
                "fields must be a dictionary"
            )

        inventory = ParameterInventory()

        for name, value in fields.items():
            if not isinstance(name, str):
                raise TypeError(
                    "parameter names must be strings"
                )

            if not name.strip():
                continue

            inventory.add(
                Parameter(
                    name=name,
                    source="form",
                    value=value,
                    location=location,
                )
            )

        return inventory

    def discover_json(
        self,
        body: object,
        *,
        location: str | None = None,
    ) -> ParameterInventory:
        if not isinstance(body, (dict, list)):
            raise TypeError(
                "JSON body must be a dictionary or list"
            )

        inventory = ParameterInventory()

        self._walk_json(
            body,
            inventory,
            location=location,
        )

        return inventory

    def _walk_json(
        self,
        value: object,
        inventory: ParameterInventory,
        *,
        location: str | None,
        prefix: str = "",
    ) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    continue

                path = (
                    f"{prefix}.{key}"
                    if prefix
                    else key
                )

                if isinstance(child, (dict, list)):
                    self._walk_json(
                        child,
                        inventory,
                        location=location,
                        prefix=path,
                    )
                else:
                    inventory.add(
                        Parameter(
                            name=key,
                            source="json",
                            value=(
                                None
                                if child is None
                                else str(child)
                            ),
                            location=location or path,
                        )
                    )

        elif isinstance(value, list):
            for index, child in enumerate(value):
                path = (
                    f"{prefix}[{index}]"
                    if prefix
                    else f"[{index}]"
                )

                if isinstance(child, (dict, list)):
                    self._walk_json(
                        child,
                        inventory,
                        location=location,
                        prefix=path,
                    )

    def discover_path(
        self,
        names: list[str] | tuple[str, ...],
        values: list[str] | tuple[str, ...],
        *,
        location: str | None = None,
    ) -> ParameterInventory:
        if len(names) != len(values):
            raise ValueError(
                "names and values must have the same length"
            )

        inventory = ParameterInventory()

        for name, value in zip(names, values):
            inventory.add(
                Parameter(
                    name=name,
                    source="path",
                    value=value,
                    location=location,
                )
            )

        return inventory

    def discover_headers(
        self,
        headers: dict[str, str],
    ) -> ParameterInventory:
        if not isinstance(headers, dict):
            raise TypeError(
                "headers must be a dictionary"
            )

        inventory = ParameterInventory()

        for name, value in headers.items():
            if not name.strip():
                continue

            inventory.add(
                Parameter(
                    name=name,
                    source="header",
                    value=value,
                )
            )

        return inventory

    def discover_cookies(
        self,
        cookies: dict[str, str],
    ) -> ParameterInventory:
        if not isinstance(cookies, dict):
            raise TypeError(
                "cookies must be a dictionary"
            )

        inventory = ParameterInventory()

        for name, value in cookies.items():
            if not name.strip():
                continue

            inventory.add(
                Parameter(
                    name=name,
                    source="cookie",
                    value=value,
                )
            )

        return inventory
