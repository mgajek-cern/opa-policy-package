from authz_service.settings import Settings


def _settings(endpoint):
    return Settings(oidc_issuer="i", oidc_audience="a", OTEL_EXPORTER_OTLP_ENDPOINT=endpoint)


def test_disabled_without_endpoint():
    assert not _settings(None).telemetry_enabled


def test_enabled_with_endpoint():
    assert _settings("http://localhost:4318").telemetry_enabled
