from m_hunter.analyzers.context import AnalysisContext


def test_analysis_context_defaults():
    context = AnalysisContext()

    assert context.response is None
    assert context.content is None
    assert context.request_url is None
    assert context.target is None
    assert context.request is None
    assert context.options == {}
    assert context.metadata == {}


def test_analysis_context_preserves_supplied_values():
    options = {"flag": True}
    metadata = {"source": "test"}
    context = AnalysisContext(
        content=b"payload",
        request_url="https://example.com/path",
        target="https://example.com",
        options=options,
        metadata=metadata,
    )

    assert context.content == b"payload"
    assert context.request_url == "https://example.com/path"
    assert context.target == "https://example.com"
    assert context.options == options
    assert context.metadata == metadata
    assert context.options is not options
    assert context.metadata is not metadata
