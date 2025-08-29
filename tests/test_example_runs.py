# tests/test_example_runs.py
# Runs examples/example_usage.py as a subprocess and asserts success.
import os
import sys
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "examples" / "example_usage.py"

def test_example_usage_success():
    assert EXAMPLE.exists(), f"Missing example script at {EXAMPLE}"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    proc = subprocess.run(
        [sys.executable, str(EXAMPLE)],
        cwd=str(REPO_ROOT),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    assert proc.returncode == 0, f"example_usage.py exited {proc.returncode}\n{out}"
    assert "All operations OK" in out, f"Did not see success line in output:\n{out}"
