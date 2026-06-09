"""Shared pytest configuration for fast deterministic tests."""

import os


# Tests validate code behavior, not GPU/model performance. Disable LLM calls
# globally before any application modules are imported.
os.environ["USE_LLM"] = "false"
os.environ["USE_LLM_REPORTS"] = "false"
