from dataclasses import dataclass, field


@dataclass(frozen=True)
class Skill:
    name: str
    category: str
    description: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    enabled: bool = True

    def __post_init__(self):
        if not self.name.strip():
            raise ValueError("name must not be empty")

        if not self.category.strip():
            raise ValueError("category must not be empty")

        normalized_tags = tuple(
            tag.strip()
            for tag in self.tags
            if tag.strip()
        )

        object.__setattr__(
            self,
            "tags",
            normalized_tags,
        )
