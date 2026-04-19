import os
import json
import time
import hashlib
import asyncio
import re
from typing import Optional

import httpx
from fastapi import HTTPException
from groq import AsyncGroq

from audit import audit, logger

groq_client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))
LOCAL_OLLAMA_ENDPOINT = os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434")
LOCAL_TIMEOUT = int(os.getenv("LOCAL_TIMEOUT", "120"))

MODEL_TIERS = {
    "nano":   os.getenv("MODEL_NANO",   "llama3.2:1b"),
    "small":  os.getenv("MODEL_SMALL",  "llama3.1:8b"),
    "medium": os.getenv("MODEL_MEDIUM", "llama3.1:8b"),
    "large":  os.getenv("MODEL_LARGE",  "llama3.1:70b"),
}

_ollama_client: Optional[httpx.AsyncClient] = None

async def get_ollama_client() -> httpx.AsyncClient:
    global _ollama_client
    if _ollama_client is None or _ollama_client.is_closed:
        _ollama_client = httpx.AsyncClient(
            base_url=LOCAL_OLLAMA_ENDPOINT,
            timeout=httpx.Timeout(connect=5, read=LOCAL_TIMEOUT, write=30, pool=10),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
    return _ollama_client

async def shutdown_ollama_client():
    global _ollama_client
    if _ollama_client:
        await _ollama_client.aclose()

_response_cache: dict[str, str] = {}
CACHE_MAX = 128

def _cache_key(text: str, model: str) -> str:
    return hashlib.sha256(f"{model}:{text[:4000]}".encode()).hexdigest()

def _from_cache(key: str) -> Optional[str]:
    return _response_cache.get(key)

def _to_cache(key: str, value: str):
    if len(_response_cache) >= CACHE_MAX:
        del _response_cache[next(iter(_response_cache))]
    _response_cache[key] = value


def select_local_model(word_count: int, risk_score: int) -> str:
    if risk_score >= 60 or word_count > 5000:
        return MODEL_TIERS["large"]
    elif word_count > 2000 or risk_score >= 30:
        return MODEL_TIERS["medium"]
    elif word_count > 400:
        return MODEL_TIERS["small"]
    return MODEL_TIERS["nano"]


def _optimal_ctx(char_count: int) -> int:
    tokens_est = char_count // 3
    ctx = tokens_est + 512
    for size in [512, 1024, 2048, 4096, 8192, 16384]:
        if ctx <= size:
            return size
    return 16384


def _max_predict(task: str) -> int:
    return {"json_analyze": 2048, "chat": 768, "summary": 512}.get(task, 1024)


async def call_local_ollama(
    text: str,
    model: str = None,
    require_json: bool = False,
    task: str = "chat",
    char_count: int = 2000,
    retries: int = 2,
    use_cache: bool = True,
) -> tuple[str, float]:
    model = model or MODEL_TIERS["small"]

    if use_cache:
        ck = _cache_key(text, model)
        cached = _from_cache(ck)
        if cached:
            logger.info(f"Cache HIT ({model})")
            return cached, 0.001

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": text}],
        "stream": False,
        "options": {
            "temperature": 0.0,
            "top_k": 10,
            "top_p": 0.9,
            "num_ctx": _optimal_ctx(char_count),
            "num_predict": _max_predict(task),
            "repeat_penalty": 1.1,
            "stop": ["```", "---END---"],
        },
    }
    if require_json:
        payload["format"] = "json"

    client = await get_ollama_client()

    for attempt in range(retries):
        t0 = time.perf_counter()
        try:
            resp = await client.post("/api/chat", json=payload)
            resp.raise_for_status()
            content = resp.json()["message"]["content"].strip()

            if require_json:
                try:
                    json.loads(content)
                except json.JSONDecodeError:
                    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
                    if m:
                        content = m.group(1)
                    else:
                        m2 = re.search(r'\{.*\}', content, re.DOTALL)
                        if m2:
                            content = m2.group(0)
                        else:
                            raise ValueError("Model did not return valid JSON.")

            elapsed = time.perf_counter() - t0
            audit.record_latency(f"ollama_{model.replace(':','_')}", elapsed)

            if use_cache:
                _to_cache(_cache_key(text, model), content)

            return content, elapsed

        except (httpx.ConnectError, httpx.RemoteProtocolError):
            global _ollama_client
            if _ollama_client:
                await _ollama_client.aclose()
            _ollama_client = None
            if attempt < retries - 1:
                await asyncio.sleep(1.5 ** attempt)
            else:
                raise HTTPException(503, "Ollama unavailable.")
        except httpx.TimeoutException:
            raise HTTPException(504, f"Local AI timed out after {LOCAL_TIMEOUT}s.")
        except ValueError as e:
            raise HTTPException(500, str(e))
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            raise HTTPException(500, "Local AI service error.")


async def call_cloud_groq(text: str, require_json: bool = False, max_tokens: int = 3000) -> tuple[str, float]:
    for attempt in range(3):
        t0 = time.perf_counter()
        try:
            kwargs: dict = {
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": text}],
                "temperature": 0.1,
                "max_tokens": max_tokens,
            }
            if require_json:
                kwargs["response_format"] = {"type": "json_object"}
            completion = await groq_client.chat.completions.create(**kwargs)
            elapsed = time.perf_counter() - t0
            audit.record_latency("groq_cloud", elapsed)
            return completion.choices[0].message.content, elapsed
        except Exception as e:
            if attempt == 2:
                raise HTTPException(500, f"Cloud provider error: {e}")
            await asyncio.sleep(2 ** attempt)

