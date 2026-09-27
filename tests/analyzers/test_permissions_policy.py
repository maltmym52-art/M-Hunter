from m_hunter.analyzers.permissions_policy import (
    PermissionsPolicyAnalyzer,
    PermissionsPolicyIndicatorType,
)
from m_hunter.core.response import HttpResponse


def response(headers=None):
    return HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers=headers or {},
        content=b"ok",
        cookies={},
        response_time=0.1,
        content_length=2,
    )


def test_missing_policy():
    analysis = PermissionsPolicyAnalyzer().analyze(response())
    assert analysis.detected
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.POLICY_MISSING
    )


def test_policy_present():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "camera=()"})
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.POLICY_PRESENT
    )


def test_camera():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "camera=()"})
    )
    assert analysis.has_type(PermissionsPolicyIndicatorType.CAMERA)


def test_microphone():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "microphone=()"})
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.MICROPHONE
    )


def test_geolocation():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "geolocation=()"})
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.GEOLOCATION
    )


def test_payment():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "payment=()"})
    )
    assert analysis.has_type(PermissionsPolicyIndicatorType.PAYMENT)


def test_usb():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "usb=()"})
    )
    assert analysis.has_type(PermissionsPolicyIndicatorType.USB)


def test_fullscreen():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "fullscreen=()"})
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.FULLSCREEN
    )


def test_display_capture():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "display-capture=()"})
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.DISPLAY_CAPTURE
    )


def test_wildcard():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "camera *"})
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.WILDCARD_SOURCE
    )


def test_self_source():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "camera self"})
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.SELF_SOURCE
    )


def test_origin_source():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response(
            {
                "Permissions-Policy":
                    "camera https://trusted.example.com"
            }
        )
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.ORIGIN_SOURCE
    )


def test_invalid_directive():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "unknown-feature *"})
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.INVALID_DIRECTIVE
    )


def test_invalid_source():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "camera evil-source"})
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.INVALID_SOURCE
    )


def test_multiple_policies():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "camera=()"})
    )
    assert analysis.has_type(
        PermissionsPolicyIndicatorType.POLICY_PRESENT
    )


def test_multiple_header_values():
    response_obj = HttpResponse(
        status_code=200,
        url="https://example.com/",
        headers={
            "Permissions-Policy": "camera=()",
        },
        content=b"ok",
        cookies={},
        response_time=0.1,
        content_length=2,
        repeated_headers={
            "Permissions-Policy": ["microphone=()"],
        },
    )

    analysis = PermissionsPolicyAnalyzer().analyze(response_obj)

    assert analysis.has_type(
        PermissionsPolicyIndicatorType.MULTIPLE_POLICIES
    )


def test_multiple_features():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response(
            {
                "Permissions-Policy":
                    "camera=(), microphone=(), geolocation=()"
            }
        )
    )

    assert analysis.has_type(PermissionsPolicyIndicatorType.CAMERA)
    assert analysis.has_type(PermissionsPolicyIndicatorType.MICROPHONE)
    assert analysis.has_type(PermissionsPolicyIndicatorType.GEOLOCATION)


def test_detected_always_true():
    analysis = PermissionsPolicyAnalyzer().analyze(response())
    assert analysis.detected is True


def test_indicator_count():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "camera *"})
    )
    assert analysis.count >= 3


def test_types_and_names():
    analysis = PermissionsPolicyAnalyzer().analyze(
        response({"Permissions-Policy": "camera self"})
    )

    assert PermissionsPolicyIndicatorType.CAMERA in analysis.types
    assert "camera" in analysis.names


def test_type_validation():
    try:
        PermissionsPolicyAnalyzer().analyze(object())
    except TypeError:
        pass
    else:
        raise AssertionError("Expected TypeError")
