import os
import subprocess
import sys


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "app.cli", *args],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )


def test_cli_allows_and_exits_zero() -> None:
    result = _run("check", "--role", "editor", "--action", "WorkflowUpdate")
    assert result.returncode == 0
    assert "ALLOW" in result.stdout
    assert "cap-edit" in result.stdout


def test_cli_denies_and_exits_one() -> None:
    result = _run("check", "--role", "viewer", "--action", "WorkflowUpdate")
    assert result.returncode == 1
    assert "DENY" in result.stdout


def test_cli_imports_no_web_stack() -> None:
    """The point of the CLI: the same engine, with no HTTP anywhere in the path."""
    result = _run("check", "--role", "viewer", "--action", "WorkflowView", "--show-imports")
    assert "fastapi" not in result.stdout
    assert "uvicorn" not in result.stdout
