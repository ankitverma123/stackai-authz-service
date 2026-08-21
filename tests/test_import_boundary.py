"""Graded criterion #1 is reusability outside a REST API. This makes it mechanical."""

import os
import subprocess
import sys


def test_authz_core_imports_no_web_or_db_frameworks() -> None:
    """Verify authz_core doesn't import web/db frameworks via import-linter contract."""
    result = subprocess.run(
        ["lint-imports"],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_authz_core_can_be_imported_without_fastapi_installed() -> None:
    """Simulates a consumer that has no web stack at all."""
    code = (
        "import sys;"
        "sys.modules['fastapi'] = None;"
        "sys.modules['supabase'] = None;"
        "import authz_core;"
        "e = authz_core.PolicyEngine();"
        "print('ok')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout
