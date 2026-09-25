from dataclasses import dataclass, field
from enum import Enum
import html
import re

from m_hunter.core.response import HttpResponse


class XSSContext(str, Enum):
    HTML_TEXT = "html_text"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    CSS = "css"
    JSON = "json"
    TEXT = "text"


@dataclass(frozen=True)
class XSSReflection:
    value: str
    context: XSSContext
    position: int
    encoded: bool = False


@dataclass
class XSSAnalysis:
    marker: str
    reflected: bool
    reflections: list[XSSReflection] = field(
        default_factory=list
    )

    @property
    def reflection_count(self) -> int:
        return len(self.reflections)

    @property
    def contexts(self) -> tuple[XSSContext, ...]:
        return tuple(
            dict.fromkeys(
                reflection.context
                for reflection in self.reflections
            )
        )

    @property
    def executable_context(self) -> bool:
        return any(
            reflection.context
            in {
                XSSContext.HTML_TEXT,
                XSSContext.HTML_ATTRIBUTE,
                XSSContext.JAVASCRIPT,
                XSSContext.URL,
                XSSContext.CSS,
            }
            for reflection in self.reflections
        )


class XSSAnalyzer:
    """
    Detects controlled marker reflection and classifies its context.

    Reflection alone is not proof of XSS execution.
    """

    def analyze(
        self,
        response: HttpResponse,
        marker: str,
    ) -> XSSAnalysis:
        if not isinstance(response, HttpResponse):
            raise TypeError(
                "response must be an instance of HttpResponse"
            )

        if not isinstance(marker, str):
            raise TypeError(
                "marker must be a string"
            )

        if not marker:
            raise ValueError(
                "marker must not be empty"
            )

        content = response.text
        reflections: list[XSSReflection] = []

        for match in re.finditer(
            re.escape(marker),
            content,
        ):
            position = match.start()

            reflections.append(
                XSSReflection(
                    value=marker,
                    context=self._classify_context(
                        content,
                        position,
                    ),
                    position=position,
                    encoded=False,
                )
            )

        encoded_variants = {
            html.escape(marker, quote=True),
            html.escape(marker, quote=False),
        }

        for encoded in encoded_variants:
            if encoded == marker:
                continue

            for match in re.finditer(
                re.escape(encoded),
                content,
            ):
                reflections.append(
                    XSSReflection(
                        value=encoded,
                        context=self._classify_context(
                            content,
                            match.start(),
                        ),
                        position=match.start(),
                        encoded=True,
                    )
                )

        reflections.sort(
            key=lambda reflection: reflection.position
        )

        return XSSAnalysis(
            marker=marker,
            reflected=bool(reflections),
            reflections=reflections,
        )

    @staticmethod
    def _classify_context(
        content: str,
        position: int,
    ) -> XSSContext:
        before = content[:position]

        if re.search(
            r"<script\b[^>]*>[^<]*$",
            before,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            return XSSContext.JAVASCRIPT

        if re.search(
            r"<style\b[^>]*>[^<]*$",
            before,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            return XSSContext.CSS

        tag_start = before.rfind("<")
        tag_end = before.rfind(">")

        if tag_start > tag_end:
            tag_fragment = before[tag_start:]

            if re.search(
                r"\b(?:href|src|action|formaction|poster|cite)"
                r"\s*=\s*['\"][^'\"]*$",
                tag_fragment,
                flags=re.IGNORECASE,
            ):
                return XSSContext.URL

            if re.search(
                r"\b[\w:-]+\s*=\s*['\"][^'\"]*$",
                tag_fragment,
            ):
                return XSSContext.HTML_ATTRIBUTE

            if re.search(
                r"\bstyle\s*=\s*['\"][^'\"]*$",
                tag_fragment,
                flags=re.IGNORECASE,
            ):
                return XSSContext.CSS

            return XSSContext.HTML_ATTRIBUTE

        if re.search(
            r"^\s*[{[]",
            content,
        ):
            return XSSContext.JSON

        if re.search(
            r"['\"](?:https?:)?//[^'\"]*$",
            before,
            flags=re.IGNORECASE,
        ):
            return XSSContext.URL

        return XSSContext.HTML_TEXT
