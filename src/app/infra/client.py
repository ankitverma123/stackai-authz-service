from functools import lru_cache

from app.settings import get_settings
from supabase import Client, create_client


@lru_cache
def get_supabase() -> Client:
    """Service-role client. Per spec D2 this bypasses RLS — the application is the
    sole enforcement point, and Task 14's route-coverage test is what backs that."""
    settings = get_settings()
    return create_client(settings.supabase_url, settings.supabase_service_role_key)
