"""LLM adapters for local Transformers and OpenAI-compatible vLLM endpoints.

The analyzer asks this module for JSON. It does not need to know whether the
response came from the local Qwen model or a remote AMD/vLLM endpoint.
"""

import json
import threading
import time
from typing import Any, cast

import requests

from backend.app.config import get_settings


def call_chat_json(messages: list[dict[str, str]], temperature: float = 0.1) -> tuple[dict[str, Any] | None, dict]:
    """Call the configured LLM provider and return parsed JSON plus metrics."""
    settings = get_settings()
    if not settings.use_llm:
        return None, _zero_metrics()
    if settings.llm_provider == "local_transformers":
        text, metrics = _generate_local_text(messages)
        return _extract_json_object(text) if text else None, metrics
    raw, metrics = _call_openai_compatible(messages, temperature, json_mode=True)
    if raw is None:
        return None, metrics
    try:
        return json.loads(raw), metrics
    except json.JSONDecodeError:
        return _extract_json_object(raw), metrics


def call_chat_text(messages: list[dict[str, str]], temperature: float = 0.2) -> tuple[str | None, dict]:
    """Call the configured LLM provider and return raw text plus metrics."""
    settings = get_settings()
    if not settings.use_llm:
        return None, _zero_metrics()
    if settings.llm_provider == "local_transformers":
        return _generate_local_text(messages)
    raw, metrics = _call_openai_compatible(messages, temperature, json_mode=False)
    return (raw.strip() if raw else None), metrics


def _zero_metrics() -> dict:
    return {"latency_seconds": 0.0, "tokens_per_second": 0.0}


def _call_openai_compatible(
    messages: list[dict[str, str]], temperature: float, *, json_mode: bool
) -> tuple[str | None, dict]:
    """Single shared HTTP call for all OpenAI-compatible endpoints."""
    settings = get_settings()
    if not settings.llm_api_base:
        return None, _zero_metrics()
    url = settings.llm_api_base.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {settings.llm_api_key}", "Content-Type": "application/json"}
    payload: dict[str, Any] = {"model": settings.llm_model, "messages": messages, "temperature": temperature}
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    timeout = 30 if json_mode else 45
    start = time.perf_counter()
    response = requests.post(url, headers=headers, json=payload, timeout=timeout)
    latency = round(time.perf_counter() - start, 3)
    response.raise_for_status()
    data = response.json()
    content: str = data["choices"][0]["message"]["content"]
    usage = data.get("usage", {})
    completion_tokens = usage.get("completion_tokens") or usage.get("total_tokens") or 0
    tokens_per_second = round(completion_tokens / latency, 2) if latency and completion_tokens else 0.0
    return content, {"latency_seconds": latency, "tokens_per_second": tokens_per_second}


# Local model objects are cached in module-level globals after the first load.
_LOCAL_MODEL = None
_LOCAL_TOKENIZER = None
_LOCAL_GENERATION_LOCK = threading.Lock()


def _generate_local_text(messages: list[dict[str, str]]) -> tuple[str | None, dict]:
    """Shared local generation helper for JSON and Markdown responses."""
    # Transformers generation over one shared model is not guaranteed to be
    # thread-safe. Serialize local GPU/CPU inference while the API remains
    # responsive through its threadpool.
    with _LOCAL_GENERATION_LOCK:
        tokenizer, model = _load_local_model()
        settings = get_settings()

        start = time.perf_counter()
        try:
            prompt = tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True, enable_thinking=False
            )
        except TypeError:
            prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer([prompt], return_tensors="pt")
        device = next(model.parameters()).device
        inputs = {key: value.to(device) for key, value in inputs.items()}
        output = model.generate(
            **inputs,
            max_new_tokens=settings.local_max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
        generated = output[0][inputs["input_ids"].shape[1] :]
        text = tokenizer.decode(generated, skip_special_tokens=True).strip()
        latency = round(time.perf_counter() - start, 3)
        tokens = int(generated.shape[0])
        tokens_per_second = round(tokens / latency, 2) if latency and tokens else 0.0
        return text, {"latency_seconds": latency, "tokens_per_second": tokens_per_second}


def _load_local_model() -> tuple[Any, Any]:
    """Load the local model once, preferring CUDA when PyTorch can access it."""
    global _LOCAL_MODEL, _LOCAL_TOKENIZER
    if _LOCAL_MODEL is not None and _LOCAL_TOKENIZER is not None:
        return _LOCAL_TOKENIZER, _LOCAL_MODEL

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    settings = get_settings()
    model_source = settings.local_model_path or settings.llm_model
    if not model_source:
        raise RuntimeError("LOCAL_MODEL_PATH or LLM_MODEL must be set for local_transformers provider.")
    local_files = bool(settings.local_model_path)
    tokenizer: Any = AutoTokenizer.from_pretrained(model_source, local_files_only=local_files)
    use_cuda = torch.cuda.is_available()
    model: Any = AutoModelForCausalLM.from_pretrained(
        model_source,
        local_files_only=local_files,
        torch_dtype=torch.float16 if use_cuda else torch.float32,
    )
    if use_cuda:
        model.to("cuda")
    model.generation_config.temperature = None
    model.generation_config.top_p = None
    model.generation_config.top_k = None
    model.eval()
    _LOCAL_TOKENIZER = tokenizer
    _LOCAL_MODEL = model
    return tokenizer, model


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """Extract the first JSON object from model text.

    Local models sometimes add surrounding prose or Markdown. The analyzer will
    ignore None and keep the rule-based result when JSON cannot be parsed.
    """
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return cast(dict[str, Any], json.loads(text[start : end + 1]))
    except json.JSONDecodeError:
        return None
