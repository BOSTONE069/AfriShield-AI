from functools import lru_cache
from os import getenv
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")
load_dotenv(ROOT / "backend" / ".env")


class Settings:
    app_name: str = getenv("APP_NAME", "AfriShield AI")
    llm_provider: str = getenv("LLM_PROVIDER", "local_transformers")
    llm_api_base: str = getenv("LLM_API_BASE", "")
    llm_api_key: str = getenv("LLM_API_KEY", "not-required")
    llm_model: str = getenv("LLM_MODEL", "Qwen/Qwen3-0.6B")
    local_model_path: str = getenv(
        "LOCAL_MODEL_PATH",
        "/home/th3c0nf3d3r4t3/.cache/huggingface/hub/models--Qwen--Qwen3-0.6B/snapshots/c1899de289a04d12100db370d81485cdf75e47ca",
    )
    local_max_new_tokens: int = int(getenv("LOCAL_MAX_NEW_TOKENS", "220"))
    runtime_gpu: str = getenv("RUNTIME_GPU", "auto")
    runtime_cloud: str = getenv("RUNTIME_CLOUD", "AMD Developer Cloud")
    runtime_backend: str = getenv("RUNTIME_BACKEND", "Transformers local")
    runtime_framework: str = getenv("RUNTIME_FRAMEWORK", "ROCm + PyTorch")
    use_llm: bool = getenv("USE_LLM", "true").lower() in {"1", "true", "yes"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
