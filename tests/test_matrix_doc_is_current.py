"""A generated doc that can go stale is worse than no doc."""

import subprocess
import sys
from pathlib import Path


def test_committed_matrix_matches_the_tests() -> None:
    generated = subprocess.run(
        [sys.executable, "scripts/generate_matrix.py"], capture_output=True, text=True, check=True
    ).stdout
    committed = Path("docs/DECISION_MATRIX.md").read_text()
    assert generated == committed, (
        "DECISION_MATRIX.md is stale — regenerate with:\n"
        "  uv run python scripts/generate_matrix.py > docs/DECISION_MATRIX.md"
    )
