from m_hunter.analyzers.context import AnalysisContext
from m_hunter.core.finding import Finding
from m_hunter.evidence import (
    EvidenceCollector,
    EvidenceService,
    InMemoryEvidenceStore,
)


def test_store_deduplicates_identical_sanitized_evidence():
    collector = EvidenceCollector()
    first = collector.capture(AnalysisContext(), evidence="same observation")
    second = collector.capture(AnalysisContext(), evidence="same observation")
    store = InMemoryEvidenceStore()

    stored_first = store.add(first)
    stored_second = store.add(second)

    assert stored_first is stored_second
    assert stored_first.id == stored_second.id
    assert len(store.all()) == 1


def test_service_associates_evidence_once_and_exports_sanitized_record():
    service = EvidenceService()
    finding = Finding(
        title="Issue",
        severity="High",
        confidence="High",
        target="https://example.test",
        evidence="Authorization: Bearer secret-value",
    )
    context = AnalysisContext(request_url="https://example.test/?token=secret")

    first = service.record(context, finding, evidence=finding.evidence)
    second = service.record(context, finding, evidence=finding.evidence)

    assert first.id == second.id
    assert finding.evidence_ids == [first.id]
    assert "secret-value" not in finding.evidence
    assert first.finding_ids == [finding.id]
    assert service.store.for_finding(finding) == (first,)
    exported = service.store.export([first.id])[0]
    assert "secret-value" not in str(exported)
    assert "token=<REDACTED>" in exported["url"]


def test_legacy_finding_is_redacted_in_display_field_and_wrapped():
    service = EvidenceService()
    finding = Finding(
        title="Legacy",
        severity="Medium",
        confidence="Low",
        target="https://example.test",
        endpoint="https://example.test/path",
        evidence="password=legacy-secret",
    )
    record = service.record_legacy_finding(finding)

    assert record.id in finding.evidence_ids
    assert finding.evidence == "password=<REDACTED>"
    assert "legacy-secret" not in str(record.to_dict())
