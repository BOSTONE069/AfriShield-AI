"""Shared pytest configuration for fast deterministic tests."""

import os
import tempfile

# Tests validate code behavior, not GPU/model performance. Disable LLM calls
# globally before any application modules are imported.
os.environ["USE_LLM"] = "false"
os.environ["USE_LLM_REPORTS"] = "false"
os.environ["AUTH_REQUIRED"] = "false"
os.environ["ALLOW_SYNC_ANALYSIS"] = "true"
os.environ["DATA_ENCRYPTION_KEY"] = "p04OD-zUVYAIcBj-xWyQnY2D5b3TJ_TgS9naEjDbyAk="
os.environ["FEEDBACK_DATABASE_PATH"] = os.path.join(tempfile.gettempdir(), "afrishield-test-feedback.db")
os.environ["LEGACY_FEEDBACK_PATH"] = os.path.join(tempfile.gettempdir(), "afrishield-no-legacy-feedback.jsonl")
