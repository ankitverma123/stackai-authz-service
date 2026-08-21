from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    supabase_url: str = Field(alias="SUPABASE_URL")
    supabase_service_role_key: str = Field(alias="SUPABASE_SERVICE_ROLE_KEY")
    supabase_jwt_secret: str = Field(alias="SUPABASE_JWT_SECRET")
    workflow_access_token_secret: str = Field(alias="WORKFLOW_ACCESS_TOKEN_SECRET")
    workflow_access_token_ttl_seconds: int = 300
    jwt_audience: str = "authenticated"
    log_level: str = "INFO"
    #: Comma-separated peer addresses allowed to set X-Forwarded-For (public.py's
    #: rate limiter). Trusting the header unconditionally would let an attacker
    #: rotate the rate-limit key at will; a plain string sidesteps pydantic-settings'
    #: JSON-decoding of list-typed env vars for what is operationally a flat list.
    trusted_proxies: str = Field(default="", alias="TRUSTED_PROXIES")


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
