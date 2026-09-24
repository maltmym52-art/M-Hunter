from m_hunter.core.skill import Skill


class SkillRegistry:
    def __init__(self):
        self._skills: dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        if not isinstance(skill, Skill):
            raise TypeError("Skill must be an instance of Skill")

        if skill.name in self._skills:
            raise ValueError(
                f"Skill already registered: {skill.name}"
            )

        self._skills[skill.name] = skill

    def get(self, name: str) -> Skill:
        try:
            return self._skills[name]
        except KeyError as exc:
            raise KeyError(
                f"Skill not found: {name}"
            ) from exc

    def get_all(self) -> list[Skill]:
        return list(self._skills.values())

    def names(self) -> list[str]:
        return list(self._skills.keys())

    def by_category(self, category: str) -> list[Skill]:
        return [
            skill
            for skill in self._skills.values()
            if skill.category == category
        ]

    def enabled(self) -> list[Skill]:
        return [
            skill
            for skill in self._skills.values()
            if skill.enabled
        ]

    def count(self) -> int:
        return len(self._skills)

    def clear(self) -> None:
        self._skills.clear()
