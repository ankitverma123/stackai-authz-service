import pytest

from app.settings import Settings


def test_settings_reject_missing_service_role_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
    monkeypatch.setenv("SUPABASE_URL", "http://localhost:54321")
    with pytest.raises(ValueError):
        Settings()


def test_settings_load_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPABASE_URL", "http://localhost:54321")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "svc")
    monkeypatch.setenv("SUPABASE_JWT_SECRET", "jwt")
    monkeypatch.setenv("WORKFLOW_ACCESS_TOKEN_SECRET", "wf")
    settings = Settings()
    assert settings.supabase_url == "http://localhost:54321"
