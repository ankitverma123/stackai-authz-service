def test_cedarpy_is_importable() -> None:
    import cedarpy

    assert hasattr(cedarpy, "is_authorized")
    assert hasattr(cedarpy, "validate_policies")
