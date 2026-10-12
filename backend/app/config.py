"""Application configuration loaded from environment files and process env.

The backend supports two inference modes:
- local_transformers: load a local Hugging Face model with PyTorch.
- openai_compatible: call a vLLM/OpenAI-compatible HTTP endpoint.
"""

from functools import lru_cache
from os import getenv
from pathlib import Path

from dotenv import load_dotenv

# Load root-level and backend-level env files so the app works whether it is
# started from the repository root or from inside the backend folder.
ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")
load_dotenv(ROOT / "backend" / ".env")


class Settings:
    """Simple settings container.

    Values are evaluated when the class is instantiated by get_settings().
    This keeps the rest of the app from repeatedly reading environment vars.
    """

    def __init__(self) -> None:
        self.app_name: str = getenv("APP_NAME", "AfriShield AI")
        self.llm_provider: str = getenv("LLM_PROVIDER", "local_transformers")
        self.llm_api_base: str = getenv("LLM_API_BASE", "")
        self.llm_api_key: str = getenv("LLM_API_KEY", "not-required")
        self.llm_model: str = getenv("LLM_MODEL", "Qwen/Qwen3-0.6B")
        self.local_model_path: str = getenv("LOCAL_MODEL_PATH", "")
        self.local_max_new_tokens: int = int(getenv("LOCAL_MAX_NEW_TOKENS", "220"))
        self.use_llm_reports: bool = getenv("USE_LLM_REPORTS", "true").lower() in {"1", "true", "yes"}
        self.runtime_gpu: str = getenv("RUNTIME_GPU", "auto")
        self.runtime_cloud: str = getenv("RUNTIME_CLOUD", "AMD Developer Cloud")
        self.runtime_backend: str = getenv("RUNTIME_BACKEND", "Transformers local")
        self.runtime_framework: str = getenv("RUNTIME_FRAMEWORK", "ROCm + PyTorch")
        self.use_llm: bool = getenv("USE_LLM", "true").lower() in {"1", "true", "yes"}
        self.max_upload_bytes: int = int(getenv("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))
        self.max_pdf_pages: int = int(getenv("MAX_PDF_PAGES", "50"))
        self.max_extracted_chars: int = int(getenv("MAX_EXTRACTED_CHARS", "20000"))
        self.max_parser_seconds: float = float(getenv("MAX_PARSER_SECONDS", "8"))
        self.max_parser_memory_mb: int = int(getenv("MAX_PARSER_MEMORY_MB", "256"))
        self.auth_required: bool = getenv("AUTH_REQUIRED", "true").lower() in {"1", "true", "yes"}
        self.api_keys: str = getenv("AFRISHIELD_API_KEYS", "")
        self.rate_limit_requests: int = int(getenv("RATE_LIMIT_REQUESTS", "60"))
        self.rate_limit_window_seconds: int = int(getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
        self.data_encryption_key: str = getenv("DATA_ENCRYPTION_KEY", getenv("AFRISHIELD_DATA_ENCRYPTION_KEY", ""))
        self.feedback_database_path: Path = Path(getenv("FEEDBACK_DATABASE_PATH", str(ROOT / "data/feedback.db")))
        self.legacy_feedback_path: Path = Path(getenv("LEGACY_FEEDBACK_PATH", str(ROOT / "data/feedback.jsonl")))
        self.feedback_retention_days: int = int(getenv("FEEDBACK_RETENTION_DAYS", "90"))
        self.audit_log_path: Path | None = Path(value) if (value := getenv("AUDIT_LOG_PATH", "").strip()) else None
        self.audit_retention_days: int = int(getenv("AUDIT_RETENTION_DAYS", "30"))
        self.analysis_workers: int = int(getenv("ANALYSIS_WORKERS", "2"))
        self.analysis_queue_size: int = int(getenv("ANALYSIS_QUEUE_SIZE", "32"))
        self.analysis_job_retention_seconds: int = int(getenv("ANALYSIS_JOB_RETENTION_SECONDS", "3600"))
        self.allow_sync_analysis: bool = getenv("ALLOW_SYNC_ANALYSIS", "false").lower() in {"1", "true", "yes"}


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings object for consistent app-wide configuration."""
    return Settings()
