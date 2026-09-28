from dataclasses import dataclass

from m_hunter.analyzers.result import AnalysisResult


@dataclass
class CustomAnalysis:
    detected: bool


def test_analysis_result_defaults():
    result = AnalysisResult(analyzer_name="example", data={"found": True})

    assert result.status == "success"
    assert result.errors == []
    assert result.metadata == {}


def test_analysis_result_preserves_data_object_and_type():
    data = CustomAnalysis(detected=True)

    result = AnalysisResult(analyzer_name="custom", data=data)

    assert result.data is data
    assert type(result.data) is CustomAnalysis


def test_analysis_result_preserves_optional_fields():
    result = AnalysisResult(
        analyzer_name="example",
        data=[1, 2],
        status="partial",
        errors=["one warning"],
        metadata={"elapsed": 0.2},
    )

    assert result.status == "partial"
    assert result.errors == ["one warning"]
    assert result.metadata == {"elapsed": 0.2}
