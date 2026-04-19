
import os, json, re, logging, time, hashlib, base64, secrets, asyncio, unicodedata
from typing import Optional
from collections import defaultdict
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Security, Depends, Request
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from groq import AsyncGroq
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

load_dotenv()


from audit import audit, logger
from crypto import e2e
from nlp import nlp
from rate_limit import rate_limiter
from api_models import *
from llm_router import get_ollama_client, call_local_ollama, call_cloud_groq, select_local_model, _response_cache, CACHE_MAX, _cache_key, _from_cache, _to_cache, MODEL_TIERS, shutdown_ollama_client
from prompts import _build_analyze_prompt, _build_chat_prompt, build_analyze_response, NORMAL_DISCLAIMER

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(request: Request, api_key: str = Security(API_KEY_HEADER)):
    # ⚡ CORS preflight carries no credentials — pass through immediately.
    # CORSMiddleware handles the actual OPTIONS response; we must not block it.
    if request.method == "OPTIONS":
        return None
    key_id = api_key or request.client.host
    if not rate_limiter.check(key_id):
        audit.log("RATE_LIMIT_EXCEEDED", key_prefix=str(key_id)[:8])
        raise HTTPException(429, "Rate limit exceeded. Retry after 60s.")
    return api_key

app = FastAPI(
    title="Sentinal Legal Engine v4.1 — Speed Edition",
    description="⚡ Fast Local · 🧠 Deep NLP · 💬 Smart Chat · 🔐 E2E (cloud only)",
    version="4.1.0",
)

@app.on_event("shutdown")
async def shutdown_event():
    await shutdown_ollama_client()

# ⚠️  ORDER MATTERS: CORSMiddleware must be added BEFORE @app.middleware("http").
# FastAPI/Starlette applies middleware in reverse registration order (last-added = outermost).
# If security_headers middleware is outermost, it intercepts OPTIONS before CORS can respond.
# By adding CORS first here, security_headers wraps it, and CORS runs outermost correctly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Pass OPTIONS through untouched — CORS middleware owns that response.
    if request.method == "OPTIONS":
        return await call_next(request)
    resp = await call_next(request)
    resp.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self' http://localhost:* http://127.0.0.1:*; connect-src 'self' http://localhost:* http://127.0.0.1:*",
        "X-Request-ID": secrets.token_hex(8),
        "X-Powered-By": "SentinalLegal/4.1",
    })
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health", tags=["System"])
async def health():
    ollama_ok = False
    try:
        c = await get_ollama_client()
        r = await c.get("/api/tags")
        ollama_ok = r.status_code == 200
    except Exception:
        pass
    return {
        "status": "operational", "version": "4.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "ollama_local": "up" if ollama_ok else "down",
            "groq_cloud": "configured" if os.getenv("GROQ_API_KEY") else "not configured",
            "e2e_encryption": "active (cloud-only — X25519-HKDF-AES256GCM)",
            "nlp_pipeline": "active (12 stages; fast-path skips 9/10/11 for short local docs)",
            "response_cache": f"{len(_response_cache)}/{CACHE_MAX} entries",
        },
        "performance": audit.get_metrics(),
    }


@app.post("/handshake", response_model=HandshakeResponse, tags=["Encryption"])
async def key_exchange(req: HandshakeRequest):
    try:
        server_pub = e2e.derive_session_key(req.client_public_key, req.session_id)
        return HandshakeResponse(server_public_key=server_pub, session_id=req.session_id)
    except Exception as ex:
        raise HTTPException(400, f"Handshake failed: {ex}")


class TranslateRequest(BaseModel):
    report: dict
    target_language: str = Field("hi", pattern="^(en|hi)$")
    mode: str = Field("local", pattern="^(local|cloud)$")

@app.post("/translate_report", tags=["Analysis"])
async def translate_report(req: TranslateRequest, api_key: str = Depends(verify_api_key)):
    lang_str = "Hindi" if req.target_language == "hi" else "English"
    
    payload = {
        "summary": req.report.get("summary", ""),
        "negotiation_strategy": req.report.get("negotiation_strategy", ""),
        "missing_protections": req.report.get("missing_protections", []),
        "rights_waived": req.report.get("rights_waived", []),
        "risks": req.report.get("risks", [])
    }
    
    prompt = f"""You are an expert legal translator. Translate all textual values in the following JSON into {lang_str}. 
IMPORTANT RULES:
1. DO NOT translate the JSON keys.
2. DO NOT change the structure or lists of the JSON.
3. Output ONLY valid JSON, with no markdown formatting.

JSON to translate:
{json.dumps(payload)}
"""
    if req.mode == "local":
        raw, _ = await call_local_ollama(prompt, require_json=True, task="translate", char_count=len(prompt), use_cache=True)
    else:
        raw, _ = await call_cloud_groq(prompt, require_json=True, max_tokens=4000)
        
    try:
        translated_payload = json.loads(raw)
        new_report = req.report.copy()
        new_report.update(translated_payload)
        new_report["_lang"] = req.target_language
        return new_report
    except Exception as e:
        logger.error(f"Translation failed: {e}")
        raise HTTPException(500, f"Translation failed: {e}")

# ── /analyze/encrypted — CLOUD CLIENTS ONLY (still fully encrypted) ─────────
@app.post("/analyze/encrypted", response_model=EncryptedResponse, tags=["Analysis"])
async def analyze_encrypted(payload: EncryptedPayload, api_key: str = Depends(verify_api_key)):
    try:
        plaintext = e2e.decrypt(payload.ciphertext, payload.nonce, payload.session_id)
        req = AnalyzeRequest(**json.loads(plaintext))
    except Exception as ex:
        raise HTTPException(400, f"Decryption error: {ex}")
    result = await _core_analyze(req)
    encrypted = e2e.encrypt(result.model_dump_json(), payload.session_id)
    return EncryptedResponse(**encrypted)


# ── /analyze — LOCAL (plaintext, no crypto overhead) ────────────────────────
@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze(req: AnalyzeRequest, api_key: str = Depends(verify_api_key)):
    return await _core_analyze(req)


async def _core_analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    request_id = secrets.token_hex(12)
    t0 = time.perf_counter()

    # ⚡ v4.1: smaller max_chars for local (fits 8b ctx window faster)
    #          full 25k for cloud where tokens are cheap
    max_chars = 5000 if req.mode == "local" else 25000

    # ⚡ v4.1: fast-path NLP for short local docs — skip stages 9/10/11
    # Threshold: <500 words AND local mode → the LLM handles those patterns fine
    word_estimate = len(req.text.split())
    use_fast_path = (req.mode == "local") and (word_estimate < 500)

    nlp_result = nlp.run(req.text, max_chars=max_chars, fast_path=use_fast_path)

    audit.log("ANALYZE_REQUEST", request_id=request_id, mode=req.mode,
              words=nlp_result["word_count"], pipeline_ms=nlp_result["pipeline_ms"],
              fast_path=use_fast_path)

    from_cache = False
    prompt = _build_analyze_prompt(nlp_result, nlp_result["primary_chunk"], req.language)

    if req.mode == "local":
        model = select_local_model(nlp_result["word_count"], nlp_result["risk_density"]["density_score"])
        ck = _cache_key(prompt, model)
        cached_content = _from_cache(ck)
        if cached_content:
            content, from_cache = cached_content, True
        else:
            content, _ = await call_local_ollama(
                prompt, model=model, require_json=True,
                task="json_analyze", char_count=len(prompt), use_cache=True
            )
    else:
        model = "llama-3.3-70b-versatile (Groq)"
        content, _ = await call_cloud_groq(prompt, require_json=True, max_tokens=3000)

    try:
        data = json.loads(content)
        data["language"] = req.language
    except json.JSONDecodeError:
        logger.error(f"[{request_id}] JSON parse failed: {content[:200]}")
        raise HTTPException(500, "Model returned invalid JSON. Try cloud mode for complex documents.")

    total_time = time.perf_counter() - t0
    audit.record_latency("total_analyze", total_time)
    response = build_analyze_response(data, nlp_result, model, total_time, request_id, from_cache)
    audit.log("ANALYZE_RESPONSE", request_id=request_id, safety=response.safety_score,
              risks=len(response.risks), time_s=round(total_time, 2), cache=from_cache)
    return response


def format_markdown_report(data: AnalyzeResponse) -> str:
    """Format analysis results as a Markdown redline report."""
    score = data.safety_score
    verdict = "✅ Broadly Acceptable" if score >= 75 else "⚠️ Needs Negotiation" if score >= 45 else "🚨 Reject / Seek Counsel"

    md = f"# Sentinal Legal Engine — Redline Report\n\n"
    md += f"**Contract Type:** {data.contract_type}  \n"
    md += f"**Safety Score:** {score} / 100  \n"
    md += f"**Overall Verdict:** {verdict}  \n\n---\n\n"
    md += f"## Executive Summary\n{data.summary}\n\n"
    md += f"## Negotiation Strategy\n{data.negotiation_strategy}\n\n---\n\n"

    if data.rights_waived:
        md += "## 🚫 Rights You Are Signing Away\n"
        for r in data.rights_waived:
            md += f"\n### {r.right}\n"
            md += f"**Triggered by:** *\"{r.clause}\"*\n\n"
            md += f"{r.detail}\n"
        md += "\n---\n\n"

    if data.missing_protections:
        md += "## ⚠️ Blind Spots — Missing Protections\n"
        for p in data.missing_protections:
            md += f"- {p}\n"
        md += "\n---\n\n"

    md += "## Risk Clauses & Proposed Rewrites\n\n"
    for i, r in enumerate(data.risks, 1):
        md += f"### {i}. [{r.risk_level.upper()} RISK]\n"
        md += f"> {r.clause}\n\n"
        md += f"**Financial Exposure:** 💸 {r.financial_exposure}\n\n"
        md += f"**Why it's dangerous:** {r.explanation}\n\n"
        md += f"**Market Benchmark:** *{r.market_benchmark}*\n\n"
        md += f"**Proposed Safe Rewrite:**\n```text\n{r.safe_rewrite}\n```\n\n---\n\n"

    return md


# ── /chat — LOCAL (plaintext, no crypto overhead) ───────────────────────────
@app.post("/chat", response_model=ChatResponse, tags=["Chat"])
async def chat_with_ai(req: ChatRequest, api_key: str = Depends(verify_api_key)):
    t0 = time.perf_counter()

    nlp_result = None
    if req.context.strip():
        # ⚡ v4.1: short context in chat → fast-path NLP (skip stages 9/10/11)
        ctx_words = len(req.context.split())
        use_fast_path = (req.mode == "local") and (ctx_words < 300)
        nlp_result = nlp.run(req.context, max_chars=6000, fast_path=use_fast_path)

    prompt = _build_chat_prompt(req.message, req.context, nlp_result, req.persona, req.history, req.language)

    if req.mode == "local":
        raw, _ = await call_local_ollama(
            prompt, require_json=True, task="chat",
            char_count=len(prompt), use_cache=False
        )
        model_info = f"Local Ollama ({MODEL_TIERS['small']})"
    else:
        raw, _ = await call_cloud_groq(prompt, require_json=True, max_tokens=1200)
        model_info = "Cloud Groq (llama-3.3-70b)"

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {
            "answer": raw,
            "recommendations": [
                "Review the contract carefully before signing.",
                "Consult a legal professional for binding advice.",
            ],
            "follow_up_questions": ["What specific clause concerns you most?"],
            "risk_flag": "Unknown — structured response unavailable"
        }

    total_time = time.perf_counter() - t0
    audit.record_latency("total_chat", total_time)

    return ChatResponse(
        response=parsed.get("answer", raw) + NORMAL_DISCLAIMER,
        recommendations=parsed.get("recommendations", []),
        follow_up_questions=parsed.get("follow_up_questions", []),
        risk_flag=parsed.get("risk_flag", "None"),
        mode_used=req.mode,
        processing_time=round(total_time, 2),
        model_info=model_info,
    )


@app.post("/export", response_class=PlainTextResponse, tags=["Analysis"])
async def export_report(data: AnalyzeResponse, api_key: str = Depends(verify_api_key)):
    """Export analysis results as a Markdown redline report."""
    try:
        return PlainTextResponse(
            content=format_markdown_report(data),
            media_type="text/markdown",
            headers={"Content-Disposition": 'attachment; filename="sentinal-redline-report.md"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export error: {str(e)}")


@app.delete("/session/{session_id}", tags=["Encryption"])
async def invalidate_session(session_id: str, api_key: str = Depends(verify_api_key)):
    e2e.invalidate(session_id)
    audit.log("SESSION_INVALIDATED", session_prefix=session_id[:8])
    return {"status": "invalidated", "session_id": session_id}


@app.get("/models", tags=["System"])
async def list_models():
    return {
        "local_tiers": MODEL_TIERS,
        "cloud_model": "llama-3.3-70b-versatile",
        "selection_logic": {
            "nano":   "<400 words AND risk<30",
            "small":  "400-2000 words OR risk 0-30",
            "medium": "2000-5000 words OR risk 30-60",
            "large":  ">5000 words OR risk>=60",
        },
        "v41_speed_changes": [
            "E2E encryption removed from /analyze and /chat (local paths are plaintext)",
            "NLP fast-path: stages 9/10/11 skipped for local docs <500 words",
            "Chat NLP fast-path: stages 9/10/11 skipped for local context <300 words",
            "Local max_chars reduced 7000→5000 (fits llama3.1:8b ctx window faster)",
        ],
        "speed_optimizations": [
            "Persistent HTTP connection pool (no TCP handshake per request)",
            "Dynamic num_ctx sizing (actual input length, not fixed 8192)",
            "Per-task num_predict caps (chat:768, analyze:2048, summary:512)",
            "SHA-256 response cache (128-entry FIFO eviction)",
            "Prompt compression (strips sig blocks, collapses whitespace)",
            "Early-stop tokens (``` and ---END---)",
            "Fast-fail retry (2 attempts, 1.5x backoff)",
        ],
    }


@app.get("/metrics", tags=["System"])
async def metrics():
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cache_utilization": f"{len(_response_cache)}/{CACHE_MAX}",
        "latency_percentiles": audit.get_metrics(),
    }


@app.delete("/cache", tags=["System"])
async def clear_cache(api_key: str = Depends(verify_api_key)):
    count = len(_response_cache)
    _response_cache.clear()
    return {"status": "cache cleared", "entries_removed": count}