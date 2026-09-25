from dataclasses import dataclass, field
import re

from m_hunter.core.response import HttpResponse


@dataclass(frozen=True)
class SQLiIndicator:
    name: str
    category: str
    evidence: str
    position: int


@dataclass
class SQLiAnalysis:
    indicators: list[SQLiIndicator] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return bool(self.indicators)

    @property
    def indicator_count(self) -> int:
        return len(self.indicators)

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                indicator.category
                for indicator in self.indicators
            )
        )

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                indicator.name
                for indicator in self.indicators
            )
        )


class SQLiAnalyzer:
    """
    Detects database-error indicators in an HTTP response.

    Error evidence is an indicator only. It does not by itself
    prove SQL injection.
    """

    ERROR_PATTERNS = {
        "mysql": (
            r"you have an error in your sql syntax",
            r"warning:\s*mysql",
            r"mysql server version",
            r"mysqli?_",
        ),
        "postgresql": (
            r"postgresql.*error",
            r"pg_query\(",
            r"psql:\s*error",
            r"unterminated quoted string at or near",
        ),
        "mssql": (
            r"microsoft sql server",
            r"odbc sql server driver",
            r"sqlserver",
            r"unclosed quotation mark after the character string",
        ),
        "oracle": (
            r"ora-\d{5}",
            r"oracle database",
            r"oracle error",
        ),
        "sqlite": (
            r"sqlite error",
            r"sqlite3\.(?:operational|database)error",
            r"no such table:\s*\w+",
        ),
        "generic": (
            r"sql syntax.*error",
            r"database error",
            r"db error",
            r"sqlstate\[[0-9a-z]+\]",
        ),
    }

    def analyze(self, response: HttpResponse) -> SQLiAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an HttpResponse"
            )

        content = response.text
        indicators: list[SQLiIndicator] = []

        for category, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(
                    pattern,
                    content,
                    re.IGNORECASE,
                )

                if match is None:
                    continue

                indicators.append(
                    SQLiIndicator(
                        name=f"{category}_error",
                        category=category,
                        evidence=match.group(0),
                        position=match.start(),
                    )
                )

        return SQLiAnalysis(
            indicators=indicators
        )
