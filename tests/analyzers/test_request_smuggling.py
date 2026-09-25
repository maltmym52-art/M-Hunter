import pytest

from m_hunter.analyzers.request_smuggling import (
    RequestSmugglingAnalysis,
    RequestSmugglingAnalyzer,
    SmugglingIndicatorType,
    SmugglingType,
)


@pytest.fixture
def analyzer():
    return RequestSmugglingAnalyzer()


def test_empty_headers(analyzer):
    result = analyzer.analyze({})

    assert isinstance(result, RequestSmugglingAnalysis)
    assert result.detected is False
    assert result.indicator_count == 0
    assert result.smuggling_types == []
    assert result.types == []
    assert result.names == []
    assert result.indicators == []


def test_normal_content_length_request(analyzer):
    result = analyzer.analyze(
        {"Content-Length": "10"}
    )

    assert result.detected is False
    assert result.indicator_count == 0


def test_normal_chunked_request(analyzer):
    result = analyzer.analyze(
        {"Transfer-Encoding": "chunked"}
    )

    assert result.detected is False
    assert result.indicator_count == 0


def test_cl_te_conflict_is_detected(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    assert result.detected is True
    assert result.conflicting_framing_detected is True
    assert SmugglingType.CL_TE in result.smuggling_types


def test_te_cl_conflict_is_detected(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "gzip",
        }
    )

    assert result.detected is True
    assert result.conflicting_framing_detected is True
    assert SmugglingType.TE_CL in result.smuggling_types


def test_duplicate_content_length_is_detected(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": [
                "10",
                "20",
            ]
        }
    )

    assert result.detected is True
    assert result.duplicate_content_length_detected is True
    assert SmugglingType.DUPLICATE_CONTENT_LENGTH in (
        result.smuggling_types
    )


def test_multiple_transfer_encoding_tokens_are_detected(analyzer):
    result = analyzer.analyze(
        {
            "Transfer-Encoding": "gzip, chunked"
        }
    )

    assert result.detected is True
    assert result.ambiguous_transfer_encoding_detected is True
    assert SmugglingType.TE_TE in result.smuggling_types


def test_invalid_transfer_encoding_is_detected(analyzer):
    result = analyzer.analyze(
        {
            "Transfer-Encoding": "gzip"
        }
    )

    assert result.detected is True
    assert (
        SmugglingType.INVALID_TRANSFER_ENCODING
        in result.smuggling_types
    )


def test_transfer_encoding_is_case_insensitive(analyzer):
    result = analyzer.analyze(
        {
            "Transfer-Encoding": "Chunked"
        }
    )

    assert result.detected is False


def test_header_names_are_case_insensitive(analyzer):
    result = analyzer.analyze(
        {
            "content-length": "10",
            "TRANSFER-ENCODING": "chunked",
        }
    )

    assert result.conflicting_framing_detected is True
    assert SmugglingType.CL_TE in result.smuggling_types


def test_transfer_encoding_tokens_are_case_insensitive(analyzer):
    result = analyzer.analyze(
        {
            "Transfer-Encoding": "GZIP, CHUNKED"
        }
    )

    assert result.ambiguous_transfer_encoding_detected is True
    assert SmugglingType.TE_TE in result.smuggling_types


def test_header_name_whitespace_is_normalized(analyzer):
    result = analyzer.analyze(
        {
            " Content-Length ": "10",
            " Transfer-Encoding ": "chunked",
        }
    )

    assert result.conflicting_framing_detected is True


def test_transfer_encoding_whitespace_is_normalized(analyzer):
    result = analyzer.analyze(
        {
            "Transfer-Encoding": " gzip , chunked "
        }
    )

    assert result.ambiguous_transfer_encoding_detected is True


def test_multiple_header_values_are_supported(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": ["10", "10"],
        }
    )

    assert result.duplicate_content_length_detected is True


def test_duplicate_identical_content_lengths_are_still_reported(
    analyzer,
):
    result = analyzer.analyze(
        {
            "Content-Length": ["10", "10"],
        }
    )

    assert result.detected is True
    assert SmugglingType.DUPLICATE_CONTENT_LENGTH in (
        result.smuggling_types
    )


def test_duplicate_different_content_lengths_are_reported(
    analyzer,
):
    result = analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
        }
    )

    assert result.detected is True
    assert SmugglingType.DUPLICATE_CONTENT_LENGTH in (
        result.smuggling_types
    )


def test_cl_te_produces_conflicting_framing_indicator(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    indicator = next(
        item
        for item in result.indicators
        if item.type
        == SmugglingIndicatorType.CONFLICTING_FRAMING
    )

    assert indicator.smuggling_type == SmugglingType.CL_TE
    assert "Content-Length" in indicator.evidence
    assert "Transfer-Encoding" in indicator.evidence


def test_duplicate_content_length_indicator_contains_values(
    analyzer,
):
    result = analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
        }
    )

    indicator = next(
        item
        for item in result.indicators
        if item.type
        == SmugglingIndicatorType.DUPLICATE_CONTENT_LENGTH
    )

    assert "10" in indicator.evidence
    assert "20" in indicator.evidence


def test_te_te_indicator_contains_tokens(analyzer):
    result = analyzer.analyze(
        {
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    indicator = next(
        item
        for item in result.indicators
        if item.type
        == SmugglingIndicatorType.AMBIGUOUS_TRANSFER_ENCODING
    )

    assert "gzip" in indicator.evidence
    assert "chunked" in indicator.evidence


def test_invalid_transfer_encoding_indicator_contains_token(
    analyzer,
):
    result = analyzer.analyze(
        {
            "Transfer-Encoding": "gzip",
        }
    )

    indicator = next(
        item
        for item in result.indicators
        if item.smuggling_type
        == SmugglingType.INVALID_TRANSFER_ENCODING
    )

    assert "gzip" in indicator.evidence


def test_indicator_count_matches_indicators(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    assert result.indicator_count == len(result.indicators)


def test_indicator_types_are_unique(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    assert len(result.types) == len(set(result.types))


def test_indicator_names_are_unique(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    assert len(result.names) == len(set(result.names))


def test_smuggling_types_are_unique(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "gzip, chunked",
        }
    )

    assert len(result.smuggling_types) == len(
        set(result.smuggling_types)
    )


def test_no_false_positive_for_unrelated_headers(analyzer):
    result = analyzer.analyze(
        {
            "Host": "example.com",
            "User-Agent": "M-Hunter",
            "Accept": "*/*",
        }
    )

    assert result.detected is False


def test_bytes_are_not_accepted_as_header_values(analyzer):
    with pytest.raises(
        TypeError,
        match="header values must be strings or lists of strings",
    ):
        analyzer.analyze(
            {"Content-Length": b"10"}
        )


def test_non_string_list_values_are_rejected(analyzer):
    with pytest.raises(
        TypeError,
        match="header values must be strings or lists of strings",
    ):
        analyzer.analyze(
            {"Content-Length": ["10", 20]}
        )


def test_non_string_header_name_is_rejected(analyzer):
    with pytest.raises(
        TypeError,
        match="header names must be strings",
    ):
        analyzer.analyze(
            {123: "10"}
        )


def test_empty_header_name_is_rejected(analyzer):
    with pytest.raises(
        ValueError,
        match="header names must not be empty",
    ):
        analyzer.analyze(
            {"   ": "10"}
        )


def test_invalid_headers_argument_is_rejected(analyzer):
    with pytest.raises(
        TypeError,
        match="headers must be a dict",
    ):
        analyzer.analyze([])


def test_cl_te_and_duplicate_content_length_can_coexist(
    analyzer,
):
    result = analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "chunked",
        }
    )

    assert result.conflicting_framing_detected is True
    assert result.duplicate_content_length_detected is True
    assert SmugglingType.CL_TE in result.smuggling_types
    assert SmugglingType.DUPLICATE_CONTENT_LENGTH in (
        result.smuggling_types
    )


def test_multiple_transfer_encoding_values_are_combined(
    analyzer,
):
    result = analyzer.analyze(
        {
            "Transfer-Encoding": [
                "gzip",
                "chunked",
            ]
        }
    )

    assert result.ambiguous_transfer_encoding_detected is True


def test_single_chunked_token_is_not_ambiguous(analyzer):
    result = analyzer.analyze(
        {
            "Transfer-Encoding": "chunked"
        }
    )

    assert result.ambiguous_transfer_encoding_detected is False


def test_indicator_position_defaults_to_none(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
        }
    )

    assert result.indicators[0].position is None


def test_analysis_flags_are_consistent(analyzer):
    result = analyzer.analyze(
        {
            "Content-Length": ["10", "20"],
            "Transfer-Encoding": "chunked",
        }
    )

    assert result.detected is True
    assert result.indicator_count > 0
    assert result.conflicting_framing_detected is True
    assert result.duplicate_content_length_detected is True
