"""LLM adapters for local Transformers and OpenAI-compatible vLLM endpoints.

The analyzer asks this module for JSON. It does not need to know whether the
response came from the local Qwen model or a remote AMD/vLLM endpoint.
"""

import json
import time
from typing import Any

import requests

from backend.app.config import get_settings


def call_chat_json(messages: list[dict[str, str]], temperature: float = 0.1) -> tuple[dict[str, Any] | None, dict]:
    """Call the configured LLM provider and return parsed JSON plus metrics."""
    settings = get_settings()
    if not settings.use_llm:
        return None, {"latency_seconds": 0.0, "tokens_per_second": 0.0}

    if settings.llm_provider == "local_transformers":
        return _call_local_transformers(messages)

    if not settings.llm_api_base:
        # OpenAI-compatible mode needs an endpoint. Without one, callers fall
        # back to deterministic rules.
        return None, {"latency_seconds": 0.0, "tokens_per_second": 0.0}

    url = settings.llm_api_base.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {settings.llm_api_key}", "Content-Type": "application/json"}
    payload = {
        "model": settings.llm_model,
        "messages": messages,
        "temperature": temperature,
        "response_format": {"type": "json_object"},
    }

    start = time.perf_counter()
    response = requests.post(url, headers=headers, json=payload, timeout=30)
    latency = round(time.perf_counter() - start, 3)
    response.raise_for_status()
    data = response.json()
    content = data["choices"][0]["message"]["content"]
    usage = data.get("usage", {})
    completion_tokens = usage.get("completion_tokens") or usage.get("total_tokens") or 0
    tokens_per_second = round(completion_tokens / latency, 2) if latency and completion_tokens else 0.0

    return json.loads(content), {"latency_seconds": latency, "tokens_per_second": tokens_per_second}


def call_chat_text(messages: list[dict[str, str]], temperature: float = 0.2) -> tuple[str | None, dict]:
    """Call the configured LLM provider and return raw text plus metrics."""
    settings = get_settings()
    if not settings.use_llm:
        return None, {"latency_seconds": 0.0, "tokens_per_second": 0.0}
    if settings.llm_provider == "local_transformers":
        return _call_local_transformers_text(messages)
    if not settings.llm_api_base:
        return None, {"latency_seconds": 0.0, "tokens_per_second": 0.0}

    url = settings.llm_api_base.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {settings.llm_api_key}", "Content-Type": "application/json"}
    payload = {"model": settings.llm_model, "messages": messages, "temperature": temperature}
    start = time.perf_counter()
    response = requests.post(url, headers=headers, json=payload, timeout=45)
    latency = round(time.perf_counter() - start, 3)
    response.raise_for_status()
    data = response.json()
    content = data["choices"][0]["message"]["content"]
    usage = data.get("usage", {})
    completion_tokens = usage.get("completion_tokens") or usage.get("total_tokens") or 0
    tokens_per_second = round(completion_tokens / latency, 2) if latency and completion_tokens else 0.0
    return content.strip(), {"latency_seconds": latency, "tokens_per_second": tokens_per_second}


# Local model objects are cached in memory after the first request. This avoids
# reloading model weights for every analysis call.
_LOCAL_MODEL = None
_LOCAL_TOKENIZER = None


def _call_local_transformers(messages: list[dict[str, str]]) -> tuple[dict[str, Any] | None, dict]:
    """Run one chat-style generation request with the local Transformers model."""
    tokenizer, model = _load_local_model()
    settings = get_settings()

    start = time.perf_counter()
    try:
        # Qwen3 supports enable_thinking=False; older tokenizers may not.
        prompt = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
            enable_thinking=False,
        )
    except TypeError:
        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)

    inputs = tokenizer([prompt], return_tensors="pt")
    device = next(model.parameters()).device
    # Inputs must be on the same device as the model. On this workstation that
    # is normally cuda when the RTX GPU is visible.
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

    return _extract_json_object(text), {"latency_seconds": latency, "tokens_per_second": tokens_per_second}


def _call_local_transformers_text(messages: list[dict[str, str]]) -> tuple[str | None, dict]:
    """Run local model generation and return the text without JSON parsing."""
    text, metrics = _generate_local_text(messages)
    return text, metrics


def _generate_local_text(messages: list[dict[str, str]]) -> tuple[str | None, dict]:
    """Shared local generation helper for JSON and Markdown responses."""
    tokenizer, model = _load_local_model()
    settings = get_settings()

    start = time.perf_counter()
    try:
        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
    except TypeError:
        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer([prompt], return_tensors="pt")
    device = next(model.parameters()).device
    inputs = {key: value.to(device) for key, value in inputs.items()}
    output = model.generate(**inputs, max_new_tokens=settings.local_max_new_tokens, do_sample=False, pad_token_id=tokenizer.eos_token_id)
    generated = output[0][inputs["input_ids"].shape[1] :]
    text = tokenizer.decode(generated, skip_special_tokens=True).strip()
    latency = round(time.perf_counter() - start, 3)
    tokens = int(generated.shape[0])
    tokens_per_second = round(tokens / latency, 2) if latency and tokens else 0.0
    return text, {"latency_seconds": latency, "tokens_per_second": tokens_per_second}


def _load_local_model():
    """Load the local model once, preferring CUDA when PyTorch can access it."""
    global _LOCAL_MODEL, _LOCAL_TOKENIZER
    if _LOCAL_MODEL is not None and _LOCAL_TOKENIZER is not None:
        return _LOCAL_TOKENIZER, _LOCAL_MODEL

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    settings = get_settings()
    model_source = settings.local_model_path or settings.llm_model
    _LOCAL_TOKENIZER = AutoTokenizer.from_pretrained(model_source, local_files_only=True)
    use_cuda = torch.cuda.is_available()
    _LOCAL_MODEL = AutoModelForCausalLM.from_pretrained(
        model_source,
        local_files_only=True,
        dtype=torch.float16 if use_cuda else torch.float32,
    )
    if use_cuda:
        _LOCAL_MODEL.to("cuda")
    # Some model configs include sampling defaults. The app uses deterministic
    # generation, so clear those to avoid warnings and inconsistent outputs.
    _LOCAL_MODEL.generation_config.temperature = None
    _LOCAL_MODEL.generation_config.top_p = None
    _LOCAL_MODEL.generation_config.top_k = None
    _LOCAL_MODEL.eval()
    return _LOCAL_TOKENIZER, _LOCAL_MODEL


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
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
