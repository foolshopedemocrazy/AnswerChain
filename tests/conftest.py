# File: tests/conftest.py
# Register and load a fast Hypothesis profile for everyday runs.
from hypothesis import settings

try:
    settings.register_profile(
        "fast",
        max_examples=12,   # reduce randomized cases
        deadline=None,     # disable per-example timing
        derandomize=True,  # stable runs
    )
except Exception:
    # profile may be registered during re-import; ignore
    pass

settings.load_profile("fast")
