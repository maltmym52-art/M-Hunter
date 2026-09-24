from typing import Any

from m_hunter.core.response import HttpResponse
from m_hunter.analyzers.base import BaseAnalyzer


class MetadataAnalyzer(BaseAnalyzer):
    name = "metadata"
    description = "Extracts structured metadata from HTTP responses"

    def analyze(self, response: HttpResponse) -> dict[str, Any]:
        return {
            "status_code": response.status_code,
            "status_category": response.status_category,
            "url": response.url,
            "content_type": response.get_content_type(),
            "content_length": response.content_length,
            "response_time": response.response_time,
            "is_success": response.is_success,
            "is_redirect": response.is_redirect,
            "is_client_error": response.is_client_error,
            "is_server_error": response.is_server_error,
            "is_html": response.is_html(),
            "is_json": response.is_json(),
            "is_text": response.is_text(),
            "headers": response.get_headers(),
        }
