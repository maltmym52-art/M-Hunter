import pytest

from m_hunter.core.skill import Skill


def test_skill_defaults():
    skill = Skill(
        name="xss",
        category="web",
    )

    assert skill.name == "xss"
    assert skill.category == "web"
    assert skill.description == ""
    assert skill.tags == ()
    assert skill.enabled is True


def test_skill_accepts_metadata():
    skill = Skill(
        name="xss",
        category="web",
        description="Cross-site scripting detection",
        tags=("xss", "injection"),
        enabled=False,
    )

    assert skill.description == "Cross-site scripting detection"
    assert skill.tags == ("xss", "injection")
    assert skill.enabled is False


def test_skill_is_immutable():
    skill = Skill(
        name="xss",
        category="web",
    )

    with pytest.raises(AttributeError):
        skill.name = "sqli"


def test_empty_name_is_rejected():
    with pytest.raises(ValueError, match="name must not be empty"):
        Skill(
            name="",
            category="web",
        )


def test_whitespace_name_is_rejected():
    with pytest.raises(ValueError, match="name must not be empty"):
        Skill(
            name="   ",
            category="web",
        )


def test_empty_category_is_rejected():
    with pytest.raises(
        ValueError,
        match="category must not be empty",
    ):
        Skill(
            name="xss",
            category="",
        )


def test_whitespace_category_is_rejected():
    with pytest.raises(
        ValueError,
        match="category must not be empty",
    ):
        Skill(
            name="xss",
            category="   ",
        )


def test_empty_tags_are_removed():
    skill = Skill(
        name="xss",
        category="web",
        tags=(
            "xss",
            "",
            "  ",
            "injection",
        ),
    )

    assert skill.tags == (
        "xss",
        "injection",
    )


def test_tags_are_trimmed():
    skill = Skill(
        name="xss",
        category="web",
        tags=(
            " xss ",
            " injection ",
        ),
    )

    assert skill.tags == (
        "xss",
        "injection",
    )
