import pytest

from m_hunter.core.skill import Skill
from m_hunter.core.skill_registry import SkillRegistry


def make_skill(
    name="xss",
    category="web",
    enabled=True,
):
    return Skill(
        name=name,
        category=category,
        description=f"{name} skill",
        enabled=enabled,
    )


def test_registry_starts_empty():
    registry = SkillRegistry()

    assert registry.count() == 0
    assert registry.names() == []
    assert registry.get_all() == []


def test_register_skill():
    registry = SkillRegistry()
    skill = make_skill()

    registry.register(skill)

    assert registry.count() == 1
    assert registry.get("xss") is skill


def test_register_multiple_skills():
    registry = SkillRegistry()

    first = make_skill("xss", "web")
    second = make_skill("sqli", "injection")

    registry.register(first)
    registry.register(second)

    assert registry.names() == [
        "xss",
        "sqli",
    ]


def test_get_missing_skill_raises():
    registry = SkillRegistry()

    with pytest.raises(
        KeyError,
        match="Skill not found: missing",
    ):
        registry.get("missing")


def test_duplicate_skill_raises():
    registry = SkillRegistry()

    registry.register(make_skill("xss"))

    with pytest.raises(
        ValueError,
        match="Skill already registered: xss",
    ):
        registry.register(make_skill("xss"))


def test_invalid_skill_raises():
    registry = SkillRegistry()

    with pytest.raises(
        TypeError,
        match="Skill must be",
    ):
        registry.register(object())


def test_get_all_returns_copy():
    registry = SkillRegistry()
    registry.register(make_skill())

    skills = registry.get_all()
    skills.clear()

    assert registry.count() == 1


def test_names_returns_copy():
    registry = SkillRegistry()
    registry.register(make_skill())

    names = registry.names()
    names.clear()

    assert registry.names() == ["xss"]


def test_by_category():
    registry = SkillRegistry()

    registry.register(make_skill("xss", "web"))
    registry.register(make_skill("sqli", "injection"))
    registry.register(make_skill("csrf", "web"))

    skills = registry.by_category("web")

    assert [skill.name for skill in skills] == [
        "xss",
        "csrf",
    ]


def test_by_category_returns_empty_for_unknown_category():
    registry = SkillRegistry()

    registry.register(make_skill())

    assert registry.by_category("unknown") == []


def test_enabled_returns_only_enabled_skills():
    registry = SkillRegistry()

    registry.register(make_skill("xss", enabled=True))
    registry.register(make_skill("sqli", enabled=False))
    registry.register(make_skill("csrf", enabled=True))

    assert [
        skill.name
        for skill in registry.enabled()
    ] == [
        "xss",
        "csrf",
    ]


def test_clear():
    registry = SkillRegistry()

    registry.register(make_skill("xss"))
    registry.register(make_skill("sqli"))

    registry.clear()

    assert registry.count() == 0
    assert registry.names() == []
    assert registry.get_all() == []


def test_registry_instances_are_independent():
    first = SkillRegistry()
    second = SkillRegistry()

    first.register(make_skill())

    assert first.count() == 1
    assert second.count() == 0
