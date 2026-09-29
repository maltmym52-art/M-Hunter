"""Conservative Finding identity and evidence aggregation regressions."""

from types import SimpleNamespace

import pytest

from m_hunter.application.service import ApplicationService
from m_hunter.core.finding import Finding


def finding(*, title="Shared finding", endpoint="https://example.test/a",
            evidence="proof A", cwe="CWE-79", target="https://example.test/",
            severity="Medium", confidence="High", indicator=None, description=""):
    metadata = {}
    if indicator is not None:
        metadata = {"validation": {"candidate": {"indicator": indicator}}}
    return Finding(
        title, severity, confidence, target, endpoint=endpoint,
        evidence=evidence, cwe=cwe, metadata=metadata, description=description,
    )


def deduplicate(items, service=None):
    service = service or ApplicationService()
    state = SimpleNamespace(statistics=SimpleNamespace(duplicates=0))
    unique = service._deduplicate_findings(items, state)
    return unique, state.statistics.duplicates, service


def test_identical_finding_and_evidence_is_duplicate():
    unique, duplicates, _ = deduplicate([finding(), finding()])
    assert len(unique) == 1
    assert duplicates == 1


def test_same_title_endpoint_but_different_evidence_stays_distinct():
    unique, duplicates, _ = deduplicate([
        finding(evidence="proof A"), finding(evidence="proof B"),
    ])
    assert len(unique) == 2
    assert duplicates == 0


def test_same_endpoint_but_different_cwe_stays_distinct():
    unique, duplicates, _ = deduplicate([
        finding(cwe="CWE-79"), finding(cwe="CWE-116"),
    ])
    assert len(unique) == 2
    assert duplicates == 0


@pytest.mark.parametrize("first,second", [
    ("https://example.test/a", "https://example.test/a/"),
    ("https://example.test/A", "https://example.test/a"),
    ("https://example.test/a?x=1", "https://example.test/a?x=2"),
    ("https://example.test/search?id=1", "https://example.test/search?id=2"),
    ("https://example.test/a", "https://example.test/b"),
])
def test_distinct_endpoint_paths_and_queries_stay_distinct(first, second):
    unique, duplicates, _ = deduplicate([
        finding(endpoint=first), finding(endpoint=second),
    ])
    assert len(unique) == 2
    assert duplicates == 0


def test_missing_header_and_invalid_value_are_distinct_root_causes():
    missing = finding(
        title="Missing X-Content-Type-Options Header",
        evidence="X-Content-Type-Options: <missing>", cwe="CWE-693",
    )
    invalid = finding(
        title="MIME Sniffing Protection Missing",
        evidence="invalid", cwe="CWE-693",
    )
    unique, duplicates, _ = deduplicate([missing, invalid])
    assert len(unique) == 2
    assert duplicates == 0


def test_separate_mime_sniffing_observation_is_not_absorbed_by_missing_header():
    missing = finding(
        title="Missing X-Content-Type-Options Header",
        evidence="X-Content-Type-Options: <missing>", cwe="CWE-693",
    )
    mime_observation = finding(
        title="MIME sniffing behavior observed",
        evidence="Browser interpreted response as text/html",
        cwe="CWE-693",
    )
    unique, duplicates, _ = deduplicate([missing, mime_observation])
    assert len(unique) == 2
    assert duplicates == 0


def test_different_candidate_indicators_are_not_duplicates():
    first = finding(indicator="SQLI_ERROR_BASED")
    second = finding(indicator="SQLI_BOOLEAN_BASED")
    unique, duplicates, _ = deduplicate([first, second])
    assert len(unique) == 2
    assert duplicates == 0


def test_same_candidate_indicator_and_observation_are_duplicates():
    first = finding(indicator="SQLI_ERROR_BASED")
    second = finding(indicator="SQLI_ERROR_BASED")
    unique, duplicates, _ = deduplicate([first, second])
    assert len(unique) == 1
    assert duplicates == 1


def test_equivalent_duplicate_keeps_strongest_severity_and_confidence():
    low = finding(severity="Low", confidence="Low", indicator="XSS_REFLECTED")
    medium = finding(severity="Medium", confidence="High", indicator="XSS_REFLECTED")
    unique, duplicates, _ = deduplicate([low, medium])
    assert len(unique) == 1
    assert duplicates == 1
    assert unique[0].severity == "Medium"
    assert unique[0].confidence == "High"


def test_missing_header_semantic_alias_from_scanner_and_analyzer_deduplicates():
    scanner = finding(
        title="Missing X-Content-Type-Options Header",
        evidence="X-Content-Type-Options: <missing>", cwe="CWE-693",
    )
    analyzer = finding(
        title="X-Content-Type-Options Header Missing",
        evidence="X-Content-Type-Options: <missing>", cwe="CWE-693",
    )
    unique, duplicates, _ = deduplicate([scanner, analyzer])
    assert len(unique) == 1
    assert duplicates == 1


def test_duplicate_finding_merges_distinct_evidence_records():
    service = ApplicationService()
    first = finding()
    second = finding()
    from m_hunter.analyzers.context import AnalysisContext

    context = AnalysisContext(request_url=first.endpoint, target=first.target)
    service.evidence_service.record(
        context, first, analyzer="scanner", source="scanner", evidence="proof A",
    )
    service.evidence_service.record(
        context, second, analyzer="analyzer", source="analysis", evidence="proof A",
    )

    unique, duplicates, _ = deduplicate([first, second], service)

    assert len(unique) == 1
    assert duplicates == 1
    evidence = service.evidence_service.store.for_finding(unique[0])
    assert len(evidence) == 2
    assert {item.sanitized.evidence for item in evidence} == {"proof A"}
    assert len(unique[0].evidence_ids) == 2


def test_identical_evidence_record_is_reused_when_findings_deduplicate():
    service = ApplicationService()
    first = finding()
    second = finding()
    first_record = service.evidence_service.record_legacy_finding(first)
    second_record = service.evidence_service.record_legacy_finding(second)
    assert first_record.id == second_record.id

    unique, duplicates, _ = deduplicate([first, second], service)

    assert len(unique) == 1
    assert duplicates == 1
    assert unique[0].evidence_ids == [first_record.id]
    assert len(service.evidence_service.store.for_finding(unique[0])) == 1
