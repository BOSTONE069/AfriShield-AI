import time

from backend.app.config import get_settings


class Timer:
    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *_args):
        self.end = time.perf_counter()
        self.latency_seconds = round(self.end - self.start, 3)


def runtime_payload(latency_seconds: float = 0.0, tokens_per_second: float = 0.0) -> dict:
    settings = get_settings()
    gpu = settings.runtime_gpu
    if gpu == "auto":
        gpu = _detect_compute_device()
    return {
        "gpu": gpu,
        "cloud": settings.runtime_cloud,
        "backend": settings.runtime_backend,
        "framework": settings.runtime_framework,
        "model": settings.llm_model,
        "latency_seconds": latency_seconds,
        "tokens_per_second": tokens_per_second,
        "llm_enabled": settings.use_llm
        and (settings.llm_provider == "local_transformers" or bool(settings.llm_api_base)),
        "llm_provider": settings.llm_provider,
    }


def _detect_compute_device() -> str:
    try:
        import torch

        if torch.cuda.is_available():
            return torch.cuda.get_device_name(0)
    except Exception:
        pass
    return "Local CPU"
