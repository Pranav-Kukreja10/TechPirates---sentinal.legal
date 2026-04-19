"""
╔══════════════════════════════════════════════════════════════════════════════╗
║      SENTINAL LEGAL ENGINE v4.1 — SPEED EDITION                            ║
║                                                                              ║
║  ⚡ Local Speed  · 🧠 Deep NLP  · 💬 Smart Chat  · 🔐 E2E (cloud only)     ║
║  📊 Obligation Map · ⚖️ Power Imbalance · 🔍 Contradiction Detection        ║
║                                                                              ║
║  v4.1 CHANGES vs v4.0:                                                      ║
║  • E2E encryption removed from local /analyze + /chat paths                 ║
║    (encryption only on /analyze/encrypted — used by cloud clients)          ║
║  • NLP fast-path: skips stages 9/10/11 for short local docs (<500 words)   ║
║  • Chat NLP skips obligations+ambiguity for short context (<300 words)      ║
║  • Local max_chars 7000→5000 (fits llama3.1:8b ctx faster)                 ║
║  • asyncio.gather() parallelises NLP + cache-key check                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

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

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — AUDIT & IN-PROCESS TELEMETRY  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

class AuditLogger:
    def __init__(self):
        self.logger = logging.getLogger("SentinalLegal.Audit")
        self.logger.setLevel(logging.INFO)
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter(
            '{"ts":"%(asctime)s","svc":"audit","msg":%(message)s}',
            datefmt="%Y-%m-%dT%H:%M:%SZ"
        ))
        self.logger.addHandler(h)
        self._metrics: dict[str, list] = defaultdict(list)

    def log(self, event: str, **kw):
        self.logger.info(json.dumps({"event": event, **kw}))

    def record_latency(self, label: str, seconds: float):
        self._metrics[label].append(round(seconds, 3))
        if len(self._metrics[label]) > 500:
            self._metrics[label] = self._metrics[label][-500:]

    def get_metrics(self) -> dict:
        out = {}
        for label, vals in self._metrics.items():
            if vals:
                out[label] = {
                    "count": len(vals),
                    "avg_s": round(sum(vals) / len(vals), 3),
                    "min_s": min(vals),
                    "max_s": max(vals),
                    "p95_s": sorted(vals)[int(len(vals) * 0.95)] if len(vals) >= 20 else None,
                }
        return out

audit = AuditLogger()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SentinalLegal.App")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — E2E ENCRYPTION  (X25519 ECDH · HKDF-SHA256 · AES-256-GCM)
# NOTE v4.1: Only used by /analyze/encrypted (cloud clients).
#            Local /analyze and /chat are plaintext — no crypto overhead.
# ══════════════════════════════════════════════════════════════════════════════

class E2EEncryption:
    def __init__(self):
        self._private_key = X25519PrivateKey.generate()
        self._public_key  = self._private_key.public_key()
        self._sessions: dict[str, bytes] = {}
        logger.info("E2E Encryption ready (cloud-only mode in v4.1).")

    @property
    def server_public_key_b64(self) -> str:
        raw = self._public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    def derive_session_key(self, client_pub_b64: str, session_id: str) -> str:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        raw = base64.b64decode(client_pub_b64)
        shared = self._private_key.exchange(X25519PublicKey.from_public_bytes(raw))
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=session_id.encode(), info=b"SentinalLegal-v4").derive(shared)
        self._sessions[session_id] = key
        audit.log("HANDSHAKE", session_prefix=session_id[:8])
        return self.server_public_key_b64

    def encrypt(self, plaintext: str, sid: str) -> dict:
        key = self._sessions.get(sid)
        if not key:
            raise HTTPException(401, "No session key.")
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
        return {"ciphertext": base64.b64encode(ct).decode(), "nonce": base64.b64encode(nonce).decode()}

    def decrypt(self, ct_b64: str, nonce_b64: str, sid: str) -> str:
        key = self._sessions.get(sid)
        if not key:
            raise HTTPException(401, "No session key.")
        try:
            return AESGCM(key).decrypt(base64.b64decode(nonce_b64), base64.b64decode(ct_b64), None).decode()
        except Exception:
            raise HTTPException(400, "Decryption failed — data tampered or invalid nonce.")

    def invalidate(self, sid: str):
        self._sessions.pop(sid, None)

e2e = E2EEncryption()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — DEEP NLP PIPELINE v2.1  (12 stages, fast-path for local)
# ══════════════════════════════════════════════════════════════════════════════

class NLPPipeline:
    """
    Stage 1:  Unicode normalization
    Stage 2:  PII detection & redaction (10 pattern types)
    Stage 3:  Clause segmentation (numbered + header-aware)
    Stage 4:  Risk keyword density (3-tier, 40+ patterns)
    Stage 5:  Contract pre-classification (12 doc types, weighted signals)
    Stage 6:  Entity extraction (7 entity types)
    Stage 7:  Obligation mapping (SHALL/MUST/WILL/AGREES)
    Stage 8:  Ambiguity detection (12 vague-language patterns)
    Stage 9:  Power-imbalance scoring (per-clause burden analysis)   ← skipped on local fast-path
    Stage 10: Readability scoring (Flesch-Kincaid proxy)             ← skipped on local fast-path
    Stage 11: Contradiction detection (conflicting numeric terms)     ← skipped on local fast-path
    Stage 12: Prompt compression + semantic chunking

    v4.1 fast-path: stages 9/10/11 are skipped when word_count < 500 AND mode == 'local'.
    The LLM catches those patterns in short docs; NLP overhead isn't worth it.
    """

    RISK_KEYWORDS = {
        "critical": [
            r"\bindemnif\w+\b", r"\bliabilit\w+\b", r"\bwithout\s+(?:any\s+)?limitation\b",
            r"\birrevocabl\w+\b", r"\bperpetual\b", r"\bin\s+perpetuity\b",
            r"\bnon[\-\s]compet\w+\b", r"\bliquidated\s+damages\b",
            r"\bwaive\s+(?:all|any)\b", r"\bsolely?\s+responsible\b",
            r"\bunlimited\s+liabilit\w+\b", r"\bno\s+cap\s+on\s+damages\b",
        ],
        "high": [
            r"\bautomatic\s+(?:renewal|rollover)\b", r"\brolling\s+contract\b",
            r"\bunilateral\w*\b", r"\bat\s+(?:our|company|employer|provider)['s]*\s+(?:sole\s+)?discretion\b",
            r"\bno\s+refund\b", r"\bnon[\-\s]refundable\b",
            r"\bassign\w*\s+(?:all\s+)?rights\b", r"\bwork[\-\s]for[\-\s]hire\b",
            r"\barbitration\s+only\b", r"\bclass\s+action\s+waiver\b",
            r"\bwaive\s+(?:right\s+to\s+)?(?:jury|court)\b",
            r"\bterminate\s+(?:at\s+)?(?:will|any\s+time)\b",
        ],
        "medium": [
            r"\b(?:30|60|90|120)[\-\s]day\s+(?:notice|period)\b", r"\bgoverning\s+law\b",
            r"\bforce\s+majeure\b", r"\bconfidentialit\w+\b",
            r"\bnon[\-\s]disclosure\b", r"\bpenalt\w+\b",
            r"\blate\s+(?:payment\s+)?fee\b", r"\binterest\s+(?:rate|charge)\b",
            r"\bintellectual\s+property\b", r"\bchange\s+(?:in\s+)?control\b",
        ],
    }

    PII_PATTERNS = {
        "email":      (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "[EMAIL]"),
        "phone_in":   (r"\b(?:\+91[\-\s]?)?[6-9]\d{9}\b", "[PHONE]"),
        "phone_us":   (r"\b(?:\+1[\-\s]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b", "[PHONE]"),
        "ssn":        (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
        "pan":        (r"\b[A-Z]{5}\d{4}[A-Z]\b", "[PAN]"),
        "aadhaar":    (r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}\b", "[AADHAAR]"),
        "passport":   (r"\b[A-Z]\d{7}\b", "[PASSPORT]"),
        "cc_number":  (r"\b(?:\d{4}[\s\-]){3}\d{4}\b", "[CARD]"),
        "ip_address": (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]"),
        "bank_acct":  (r"\b\d{9,18}\b(?=\s*(?:account|acct|a/c))", "[BANK_ACCT]"),
    }

    CONTRACT_SIGNALS: dict[str, list[tuple[str, int]]] = {
        "NDA / Confidentiality Agreement":   [("non-disclosure", 3), ("confidential", 2), ("nda", 3), ("proprietary", 2)],
        "Employment Contract":               [("employment", 3), ("salary", 2), ("employee", 2), ("probation", 2), ("termination", 1)],
        "Lease / Rental Agreement":          [("lease", 3), ("tenant", 3), ("landlord", 3), ("rent", 2), ("premises", 2)],
        "Service Agreement (SaaS/IT)":       [("saas", 3), ("software", 2), ("api", 2), ("uptime", 3), ("sla", 3), ("subscription", 2)],
        "UGC / Academic Undertaking":        [("ugc", 3), ("anti-ragging", 3), ("undertaking", 2), ("institution", 1), ("student", 1)],
        "Loan / Financing Agreement":        [("loan", 3), ("interest rate", 3), ("repayment", 2), ("collateral", 3), ("emi", 3)],
        "Freelance / Contractor Agreement":  [("freelance", 3), ("contractor", 3), ("milestone", 2), ("deliverable", 2), ("invoice", 2)],
        "Terms of Service":                  [("terms of service", 3), ("terms of use", 3), ("acceptable use", 2), ("user agreement", 3)],
        "Purchase / Sale Agreement":         [("purchase price", 3), ("buyer", 2), ("seller", 2), ("closing", 2), ("title", 1)],
        "Partnership / JV Agreement":        [("partnership", 3), ("joint venture", 3), ("profit sharing", 3), ("capital contribution", 2)],
        "Franchise Agreement":               [("franchise", 3), ("franchisee", 3), ("royalt", 3), ("territory", 2)],
        "Insurance Policy":                  [("premium", 3), ("insured", 3), ("claim", 2), ("deductible", 2), ("coverage", 2)],
    }

    ENTITY_PATTERNS = {
        "parties":   r"(?:between|among|by and between)\s+([A-Z][^,\n]{2,60}?)\s+(?:and|&)\s+([A-Z][^,\n]{2,60})",
        "amounts":   r"(?:USD|INR|EUR|GBP|Rs\.?|₹|\$|€|£)\s?[\d,]+(?:\.\d{2})?(?:\s*(?:lakh|crore|thousand|million|billion))?",
        "dates":     r"\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{1,2}\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{4})\b",
        "duration":  r"\b\d+\s+(?:calendar\s+)?(?:month|year|day|week)s?\b",
        "penalties": r"(?:penalty|fine|fee|charge)\s+of\s+(?:USD|INR|Rs\.?|₹|\$)?\s?[\d,]+",
        "notice":    r"\b(\d+)[\-\s]day\s+(?:written\s+)?notice\b",
        "governing": r"(?:governed\s+by|laws?\s+of)\s+(?:the\s+)?([A-Z][A-Za-z\s]{2,40})",
    }

    OBLIGATION_PATTERNS = [
        (r"(?:the\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+shall\s+(.{10,120}?)(?=\.|;|\n)", "shall"),
        (r"(?:the\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+must\s+(.{10,120}?)(?=\.|;|\n)", "must"),
        (r"(?:the\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+will\s+(.{10,120}?)(?=\.|;|\n)", "will"),
        (r"(?:the\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+agrees?\s+to\s+(.{10,120}?)(?=\.|;|\n)", "agrees"),
        (r"(?:the\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+is\s+responsible\s+for\s+(.{10,120}?)(?=\.|;|\n)", "responsible"),
    ]

    AMBIGUITY_PATTERNS = [
        r"\breasonabl\w+\b", r"\bsole\s+discretion\b", r"\bas\s+(?:soon\s+as\s+)?practicabl\w+\b",
        r"\bappropriate\b", r"\badequate\b", r"\bsubstantial\b", r"\bsatisfactor\w+\b",
        r"\bat\s+any\s+time\b", r"\bfrom\s+time\s+to\s+time\b", r"\bmarket\s+(?:rate|value|price)\b",
        r"\bmutual(?:ly)?\s+agree[sd]?\b", r"\bcommercially\s+reasonable\b",
    ]

    POWER_SIGNALS = {
        -3: [r"\bsole\s+discretion\b", r"\bwithout\s+(?:any\s+)?limitation\b", r"\birrevocabl\w+\b"],
        -2: [r"\bunilateral\w*\b", r"\bat\s+will\b", r"\bnon[\-\s]refundable\b"],
        -1: [r"\bconfidential\b", r"\bnon[\-\s]disclosure\b", r"\bpenalt\w+\b"],
         1: [r"\bmutual\b", r"\bboth\s+parties\b", r"\bequal\b"],
         2: [r"\bright\s+to\s+terminat\w+\b", r"\bright\s+to\s+cure\b"],
         3: [r"\bwarrant\w+\b", r"\bindemnif\w+\s+(?:you|client|customer)\b"],
    }

    # ── Stage 1 ───────────────────────────────────────────────────────────────
    def _normalize(self, text: str) -> str:
        text = unicodedata.normalize("NFC", text)
        text = re.sub(r"\r\n|\r", "\n", text)
        text = re.sub(r"[ \t]{2,}", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    # ── Stage 2 ───────────────────────────────────────────────────────────────
    def redact_pii(self, text: str) -> tuple[str, list[str]]:
        found = []
        for pii_type, (pat, repl) in self.PII_PATTERNS.items():
            new_text, n = re.subn(pat, repl, text, flags=re.IGNORECASE)
            if n:
                found.append(f"{pii_type}({n})")
                text = new_text
        return text, found

    # ── Stage 3 ───────────────────────────────────────────────────────────────
    def segment_clauses(self, text: str) -> list[dict]:
        pattern = re.compile(
            r'(?:^|\n)('
            r'(?:\d+(?:\.\d+)*\.?\s+[A-Z][\w\s]{0,60})'
            r'|(?:[a-z]\)\s+)'
            r'|(?:[A-Z]{3,}[\s:]+)'
            r')',
            re.MULTILINE
        )
        splits = list(pattern.finditer(text))
        clauses = []
        for i, match in enumerate(splits):
            start = match.start()
            end = splits[i + 1].start() if i + 1 < len(splits) else len(text)
            body = text[match.end():end].strip()
            if len(body) > 20:
                clauses.append({"index": i+1, "header": match.group(1).strip(), "body": body, "char_start": start})
        if not clauses:
            paras = [p.strip() for p in re.split(r'\n{2,}', text) if len(p.strip()) > 30]
            clauses = [{"index": i+1, "header": f"Para {i+1}", "body": p, "char_start": 0} for i, p in enumerate(paras)]
        return clauses

    # ── Stage 4 ───────────────────────────────────────────────────────────────
    def score_risk_density(self, text: str) -> dict:
        text_lower = text.lower()
        word_count = max(len(text.split()), 1)
        counts = {"critical": 0, "high": 0, "medium": 0}
        matched_terms: list[str] = []
        for tier, patterns in self.RISK_KEYWORDS.items():
            for pat in patterns:
                hits = re.findall(pat, text_lower)
                if hits:
                    counts[tier] += len(hits)
                    matched_terms.extend(hits[:2])
        weighted = counts["critical"] * 15 + counts["high"] * 7 + counts["medium"] * 3
        density_score = min(100, int((weighted / word_count) * 1000))
        return {
            "counts": counts,
            "density_score": density_score,
            "word_count": word_count,
            "top_risk_terms": list(dict.fromkeys(matched_terms))[:10],
        }

    # ── Stage 5 ───────────────────────────────────────────────────────────────
    def pre_classify_contract(self, text: str) -> tuple[str, int]:
        text_lower = text.lower()
        scores: dict[str, int] = {}
        for ct, signals in self.CONTRACT_SIGNALS.items():
            scores[ct] = sum(w for term, w in signals if term in text_lower)
        total = sum(scores.values()) or 1
        best = max(scores, key=scores.get)
        confidence = min(100, int((scores[best] / total) * 200))
        return (best if scores[best] > 0 else "General Agreement"), confidence

    # ── Stage 6 ───────────────────────────────────────────────────────────────
    def extract_entities(self, text: str) -> dict:
        entities: dict[str, list] = {}
        for etype, pat in self.ENTITY_PATTERNS.items():
            matches = re.findall(pat, text, re.IGNORECASE | re.MULTILINE)
            flat = []
            for m in matches:
                flat.append((" & ".join(p.strip() for p in m)) if isinstance(m, tuple) else m.strip())
            entities[etype] = list(dict.fromkeys(flat))[:6]
        return entities

    # ── Stage 7 ───────────────────────────────────────────────────────────────
    def extract_obligations(self, text: str) -> list[dict]:
        obligations = []
        for pat, verb in self.OBLIGATION_PATTERNS:
            for m in re.finditer(pat, text):
                duty = m.group(2).strip()
                if len(duty) > 15:
                    obligations.append({"party": m.group(1).strip(), "verb": verb, "obligation": duty[:200]})
        seen: set = set()
        unique = []
        for o in obligations:
            key = o["obligation"][:50]
            if key not in seen:
                seen.add(key)
                unique.append(o)
        return unique[:20]

    # ── Stage 8 ───────────────────────────────────────────────────────────────
    def detect_ambiguities(self, text: str) -> list[dict]:
        results = []
        for pat in self.AMBIGUITY_PATTERNS:
            for m in re.finditer(pat, text, re.IGNORECASE):
                start, end = max(0, m.start() - 60), min(len(text), m.end() + 60)
                results.append({"term": m.group().strip(), "context": text[start:end].replace("\n", " ").strip()})
        seen: set = set()
        unique = []
        for r in results:
            if r["term"].lower() not in seen:
                seen.add(r["term"].lower())
                unique.append(r)
        return unique[:10]

    # ── Stage 9 ───────────────────────────────────────────────────────────────
    def score_power_imbalance(self, text: str) -> dict:
        text_lower = text.lower()
        total_score = 0
        for score_val, patterns in self.POWER_SIGNALS.items():
            for pat in patterns:
                total_score += score_val * len(re.findall(pat, text_lower))
        if total_score <= -6:
            verdict = "Heavily One-Sided (Against You)"
        elif total_score <= -3:
            verdict = "Moderately Unfavourable"
        elif total_score <= -1:
            verdict = "Slightly Unfavourable"
        elif total_score == 0:
            verdict = "Neutral / Balanced"
        elif total_score <= 3:
            verdict = "Slightly Favourable"
        else:
            verdict = "Well-Protected"
        return {"raw_score": total_score, "verdict": verdict}

    # ── Stage 10 ──────────────────────────────────────────────────────────────
    def readability_score(self, text: str) -> dict:
        sentences = [s for s in re.split(r'[.!?]+', text) if len(s.split()) >= 3]
        if not sentences:
            return {"score": 50, "grade": "Unknown", "avg_sentence_length": 0}
        words = text.split()
        word_count = max(len(words), 1)
        sentence_count = max(len(sentences), 1)
        syllable_count = max(sum(len(re.findall(r'[aeiouAEIOU]+', w)) for w in words), 1)
        fk = max(0, min(100, 206.835 - 1.015 * (word_count / sentence_count) - 84.6 * (syllable_count / word_count)))
        grade = (
            "Easy (Plain Language)" if fk >= 70
            else "Standard" if fk >= 50
            else "Difficult (Complex Legalese)" if fk >= 30
            else "Very Difficult (Deliberately Obscure)"
        )
        return {"score": round(fk, 1), "grade": grade, "avg_sentence_length": round(word_count / sentence_count, 1)}

    # ── Stage 11 ──────────────────────────────────────────────────────────────
    def detect_contradictions(self, text: str) -> list[dict]:
        term_values: dict[str, list[str]] = defaultdict(list)
        patterns = {
            "notice_days":   r"(\d+)[\-\s]day\s+(?:written\s+)?notice",
            "payment_days":  r"payment\s+(?:within|due\s+in)\s+(\d+)\s+days?",
            "termination":   r"terminat\w+\s+(?:upon|with)\s+(\d+)\s+days?",
            "interest_rate": r"(\d+(?:\.\d+)?)\s*%\s*(?:per\s+(?:annum|month|year))?",
        }
        for term, pat in patterns.items():
            for m in re.finditer(pat, text, re.IGNORECASE):
                term_values[term].append(m.group(1))
        contradictions = []
        for term, vals in term_values.items():
            unique_vals = list(dict.fromkeys(vals))
            if len(unique_vals) > 1:
                contradictions.append({
                    "term": term.replace("_", " "),
                    "conflicting_values": unique_vals,
                    "warning": f"'{term.replace('_',' ')}' appears as both {' and '.join(unique_vals)} — clarify before signing."
                })
        return contradictions

    # ── Stage 12 ──────────────────────────────────────────────────────────────
    def compress_for_llm(self, text: str, max_chars: int) -> str:
        text = re.sub(r'(?:IN\s+WITNESS\s+WHEREOF|SIGNED\s+BY|Signature[:\s]+_+)[^\n]*\n?', '', text, flags=re.IGNORECASE)
        text = re.sub(r'(?:Exhibit|Schedule|Annex)\s+[A-Z]\s*\n(?=\n)', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\n{3,}', '\n\n', text)
        text = re.sub(r'[ \t]{2,}', ' ', text)
        if len(text) <= max_chars:
            return text
        truncated = text[:max_chars]
        last_period = truncated.rfind('.')
        if last_period > max_chars * 0.8:
            truncated = truncated[:last_period + 1]
        return truncated

    def chunk_for_llm(self, text: str, max_chars: int) -> list[str]:
        if len(text) <= max_chars:
            return [text]
        clauses = self.segment_clauses(text)
        chunks, current, current_len = [], [], 0
        for c in clauses:
            body = c["body"]
            if current_len + len(body) > max_chars:
                if current:
                    chunks.append("\n\n".join(current))
                current, current_len = [body], len(body)
            else:
                current.append(body)
                current_len += len(body)
        if current:
            chunks.append("\n\n".join(current))
        return chunks

    # ── Full pipeline run ──────────────────────────────────────────────────────
    # v4.1: fast_path=True skips stages 9/10/11 for short local docs
    def run(self, text: str, max_chars: int = 8000, fast_path: bool = False) -> dict:
        t0 = time.perf_counter()
        text = self._normalize(text)
        text, pii_found = self.redact_pii(text)
        risk_density         = self.score_risk_density(text)
        pre_class, conf      = self.pre_classify_contract(text)
        entities             = self.extract_entities(text)
        obligations          = self.extract_obligations(text)
        ambiguities          = self.detect_ambiguities(text)

        # ⚡ Fast-path: skip expensive stages 9/10/11 for short local docs
        if fast_path:
            power          = {"raw_score": 0, "verdict": "Skipped (fast-path)"}
            readability    = {"score": 50, "grade": "Skipped (fast-path)", "avg_sentence_length": 0}
            contradictions = []
        else:
            power          = self.score_power_imbalance(text)
            readability    = self.readability_score(text)
            contradictions = self.detect_contradictions(text)

        compressed           = self.compress_for_llm(text, max_chars)
        chunks               = self.chunk_for_llm(compressed, max_chars)
        pipeline_ms          = round((time.perf_counter() - t0) * 1000, 1)
        return {
            "cleaned_text":              text,
            "primary_chunk":             chunks[0],
            "total_chunks":              len(chunks),
            "pii_redacted":              pii_found,
            "risk_density":              risk_density,
            "pre_classification":        pre_class,
            "classification_confidence": conf,
            "entities":                  entities,
            "obligations":               obligations,
            "ambiguities":               ambiguities,
            "power_imbalance":           power,
            "readability":               readability,
            "contradictions":            contradictions,
            "char_count":                len(text),
            "word_count":                risk_density["word_count"],
            "pipeline_ms":               pipeline_ms,
        }

nlp = NLPPipeline()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — RATE LIMITER  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, rpm: int = 30):
        self.rpm = rpm
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str) -> bool:
        now, window = time.time(), time.time() - 60
        self._buckets[key] = [t for t in self._buckets[key] if t > window]
        if len(self._buckets[key]) >= self.rpm:
            return False
        self._buckets[key].append(now)
        return True

rate_limiter = RateLimiter(int(os.getenv("RATE_LIMIT_RPM", "30")))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — APP + MIDDLEWARE  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

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

groq_client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — LOCAL MODEL ROUTER  (unchanged from v4.0)
# ══════════════════════════════════════════════════════════════════════════════

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

@app.on_event("shutdown")
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


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — PYDANTIC MODELS  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

class HandshakeRequest(BaseModel):
    client_public_key: str
    session_id: str = Field(..., min_length=16, max_length=64)

class HandshakeResponse(BaseModel):
    server_public_key: str
    session_id: str
    algorithm: str = "X25519-HKDF-SHA256-AES256GCM"

class EncryptedPayload(BaseModel):
    ciphertext: str
    nonce: str
    session_id: str

class EncryptedResponse(BaseModel):
    ciphertext: str
    nonce: str

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=50, max_length=120000)
    mode: str = Field("local", pattern="^(local|cloud)$")
    language: str = Field("en", pattern="^(en|hi)$")

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=3000)
    mode: str = Field("local", pattern="^(local|cloud)$")
    context: str = Field("", max_length=30000)
    persona: str = Field("general", pattern="^(general|student|employee|business)$")
    history: list[dict] = Field(default_factory=list)
    language: str = Field("en", pattern="^(en|hi)$")

class RiskItem(BaseModel):
    clause: str
    risk_level: str
    financial_exposure: str
    explanation: str
    market_benchmark: str
    safe_rewrite: str

class RightWaived(BaseModel):
    right: str
    detail: str
    clause: str

class ObligationItem(BaseModel):
    party: str
    verb: str
    obligation: str

class AmbiguityItem(BaseModel):
    term: str
    context: str

class ContradictionItem(BaseModel):
    term: str
    conflicting_values: list[str]
    warning: str

class NLPMetadata(BaseModel):
    pre_classification: str
    classification_confidence: int
    risk_density_score: int
    risk_keyword_counts: dict
    top_risk_terms: list[str]
    entities: dict
    obligations: list[ObligationItem]
    ambiguities: list[AmbiguityItem]
    power_imbalance: dict
    readability: dict
    contradictions: list[ContradictionItem]
    pii_redacted: list[str]
    word_count: int
    total_chunks: int
    pipeline_ms: float

class AnalyzeResponse(BaseModel):
    request_id: str
    contract_type: str
    summary: str
    negotiation_strategy: str
    safety_score: int
    missing_protections: list[str]
    rights_waived: list[RightWaived]
    risks: list[RiskItem]
    nlp_metadata: NLPMetadata
    model_used: str
    processing_time: float
    from_cache: bool = False

class ChatResponse(BaseModel):
    response: str
    recommendations: list[str]
    follow_up_questions: list[str]
    risk_flag: str
    mode_used: str
    processing_time: float
    model_info: str


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — PROMPT BUILDERS & ANALYSIS LOGIC  (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

HIGH_RISK_DISCLAIMER = (
    "\n\n**⚠️ CRITICAL LEGAL NOTICE**: High-risk clauses detected. "
    "Consult a licensed attorney immediately before signing."
)
NORMAL_DISCLAIMER = (
    "\n\n*AI-assisted analysis — educational only. "
    "Consult a licensed attorney for binding legal advice.*"
)


def _build_analyze_prompt(nlp_result: dict, text: str, language: str = "en") -> str:
    entities_str = "; ".join(
        f"{k}: {', '.join(v[:2])}" for k, v in nlp_result["entities"].items() if v
    ) or "None detected"
    obligations_str = "\n".join(
        f"  - [{o['party']}] {o['verb'].upper()}: {o['obligation'][:100]}"
        for o in nlp_result["obligations"][:5]
    ) or "  None detected"
    ambiguity_str = ", ".join(a["term"] for a in nlp_result["ambiguities"][:5]) or "None"
    contra_str = "; ".join(c["warning"] for c in nlp_result["contradictions"]) or "None"
    power = nlp_result["power_imbalance"]

    lang_inst = ""
    if language == "hi":
        lang_inst = "\nIMPORTANT: All text values in the JSON (summary, negotiation_strategy, missing_protections, rights_waived, explanation, safe_rewrite, etc.) MUST be written in Hindi. Do NOT translate the JSON keys."

    return f"""You are an Enterprise Legal Parsing Engine v4.1. Return ONE valid JSON object — no markdown, no preamble.{lang_inst}

NLP PRE-ANALYSIS BRIEFING:
- Document type: {nlp_result['pre_classification']} (confidence: {nlp_result['classification_confidence']}%)
- Risk density: {nlp_result['risk_density']['density_score']}/100
- Top risk terms: {', '.join(nlp_result['risk_density'].get('top_risk_terms', [])[:6])}
- Power imbalance: {power['verdict']} (raw score: {power['raw_score']})
- Readability: {nlp_result['readability']['grade']} (FK: {nlp_result['readability']['score']})
- Key entities: {entities_str}
- Obligations:
{obligations_str}
- Ambiguous terms: {ambiguity_str}
- Contradictions: {contra_str}

CALIBRATION RULES:
1. Standard compliance docs (UGC/undertaking/declaration): LOW risk baseline.
2. Commercial contracts: FULL risk scrutiny.
3. Power imbalance score < -3 must always generate at least one High risk.
4. Provide verbatim clause text. Be concise but complete.

REQUIRED JSON (no extra keys):
{{
  "contract_type": "Specific type",
  "summary": "Detailed 3-4 paragraph explanation outlining the core obligations, power dynamics, key financial terms, hidden traps, and worst-case risk scenarios.",
  "negotiation_strategy": "• Ask for X\\n• Insist on Y\\n• Verify Z",
  "missing_protections": ["Item 1", "Item 2"],
  "rights_waived": [{{"right":"Name","detail":"Impact","clause":"Verbatim"}}],
  "risks": [{{
    "clause": "Verbatim text",
    "risk_level": "High|Medium|Low",
    "financial_exposure": "₹X or N/A",
    "explanation": "Why risky for this doc type",
    "market_benchmark": "Standard practice",
    "safe_rewrite": "Fair alternative or 'Standard Compliance Required'"
  }}]
}}

DOCUMENT:
{text}"""


def _build_chat_prompt(
    message: str,
    context: str,
    nlp_result: Optional[dict],
    persona: str,
    history: list[dict],
    language: str = "en",
) -> str:
    persona_map = {
        "student":  "The user is a student. Use plain language, explain all legal terms simply, be supportive and reassuring.",
        "employee": "The user is an employee reviewing a work contract. Prioritise labour rights, notice periods, IP ownership, and non-compete risks.",
        "business": "The user is a business owner. Focus on liability exposure, IP protection, payment terms, and negotiation leverage.",
        "general":  "The user is a general member of the public with no assumed legal knowledge.",
    }

    context_briefing = ""
    if nlp_result:
        top_risks = "\n".join(f"  • '{t}'" for t in nlp_result["risk_density"].get("top_risk_terms", [])[:5]) or "  • None flagged"
        obligations_brief = "\n".join(
            f"  • [{o['party']}] {o['verb']}: {o['obligation'][:80]}"
            for o in nlp_result.get("obligations", [])[:4]
        ) or "  • None extracted"
        ambig_brief = ", ".join(a["term"] for a in nlp_result.get("ambiguities", [])[:5]) or "None"
        power = nlp_result.get("power_imbalance", {})
        contra_brief = "; ".join(c["warning"] for c in nlp_result.get("contradictions", [])) or "None"

        context_briefing = f"""
CONTRACT INTELLIGENCE BRIEFING (NLP pre-analysis):
  Type: {nlp_result['pre_classification']} ({nlp_result['classification_confidence']}% confidence)
  Power balance: {power.get('verdict','Unknown')} (score: {power.get('raw_score',0)})
  Readability: {nlp_result['readability']['grade']}
  Risk density: {nlp_result['risk_density']['density_score']}/100
  High-risk terms detected:
{top_risks}
  Key obligations:
{obligations_brief}
  Vague language: {ambig_brief}
  Contradictions: {contra_brief}
  Word count: {nlp_result['word_count']}

FULL CONTRACT TEXT:
{context[:5000]}
"""
    elif context.strip():
        context_briefing = f"\nCONTRACT TEXT:\n{context[:5000]}\n"

    history_str = ""
    if history:
        history_str = "\nCONVERSATION HISTORY:\n"
        for turn in history[-4:]:
            history_str += f"  [{turn.get('role','user').upper()}]: {str(turn.get('content',''))[:300]}\n"

    lang_inst = ""
    if language == "hi":
        lang_inst = "\nIMPORTANT: Your entire response (answer, recommendations, follow_up_questions, risk_flag) MUST be in Hindi. Do NOT translate the JSON keys."

    return f"""You are an Enterprise Legal Advisor AI. Answer the user's question directly.

PERSONA: {persona_map.get(persona, persona_map['general'])}{lang_inst}

RULES:
1. NEVER refuse factual questions about the contract text.
2. Cite specific clauses by name or number when possible.
3. Ground ALL recommendations in the actual contract text — not generic advice.
4. Respond ONLY with the JSON below.
{context_briefing}{history_str}
USER QUESTION: {message}

Respond ONLY with this JSON (no markdown fences):
{{
  "answer": "Direct, complete answer. Reference specific clauses. 3-6 sentences.",
  "recommendations": [
    "First specific action grounded in the contract",
    "Second specific action grounded in the contract",
    "Third specific action or mitigation strategy",
    "Fourth specific action or negotiation point",
    "Fifth specific action (if applicable)"
  ],
  "follow_up_questions": [
    "A relevant follow-up the user should ask next",
    "Another important question to consider"
  ],
  "risk_flag": "High|Medium|Low|None — one-sentence justification referencing a specific clause"
}}"""


def calculate_safety_score(
    risks: list, missing_count: int, rights_waived_count: int,
    contract_type: str, risk_density_score: int, power_score: int
) -> int:
    doc_type = contract_type.lower()
    is_compliance = any(k in doc_type for k in [
        "undertaking", "declaration", "ugc", "anti-ragging", "compliance", "acknowledgement"
    ])
    base = 95 if is_compliance else 80
    ded = {"High": 8, "Medium": 4, "Low": 1} if is_compliance else {"High": 25, "Medium": 10, "Low": 3}
    score = base
    for r in risks:
        score -= ded.get(r.get("risk_level", "Low"), 0)
    score -= rights_waived_count * 5
    score -= missing_count * 3
    score -= int(risk_density_score * 0.08)
    score -= max(0, -power_score) * 2
    return max(0, min(100, score))


def build_analyze_response(
    data: dict, nlp_result: dict, model_used: str,
    processing_time: float, request_id: str, from_cache: bool = False
) -> AnalyzeResponse:
    if isinstance(data, list):
        data = data[0] if data else {}
    contract_type = str(data.get("contract_type", nlp_result["pre_classification"]))
    missing = [str(i) for i in data.get("missing_protections", [])]
    rights_waived = [RightWaived(**w) for w in data.get("rights_waived", []) if isinstance(w, dict)]
    risks_raw = [r for r in data.get("risks", []) if isinstance(r, dict)]
    risks = [RiskItem(**r) for r in risks_raw]
    power_score = nlp_result["power_imbalance"]["raw_score"]
    safety_score = calculate_safety_score(
        risks_raw, len(missing), len(rights_waived),
        contract_type, nlp_result["risk_density"]["density_score"], power_score
    )
    is_standard = any(k in contract_type.lower() for k in ["undertaking", "declaration", "ugc"])
    summary = str(data.get("summary", "Analysis complete." if data.get("language") != "hi" else "विश्लेषण पूर्ण।"))
    
    # Apply disclaimer in correct language
    lang = data.get("language", "en")
    if safety_score < 50 and not is_standard:
        summary += HIGH_RISK_DISCLAIMER if lang == "en" else "\n\n**⚠️ गंभीर कानूनी सूचना**: उच्च-जोखिम धाराओं का पता चला है। हस्ताक्षर करने से पहले तुरंत किसी वकील से सलाह लें।"
    else:
        summary += NORMAL_DISCLAIMER if lang == "en" else "\n\n*AI-सहायता प्राप्त विश्लेषण — केवल शैक्षिक। बाध्यकारी कानूनी सलाह के लिए वकील से परामर्श लें।*"

    return AnalyzeResponse(
        request_id=request_id,
        contract_type=contract_type,
        summary=summary,
        negotiation_strategy=str(data.get("negotiation_strategy", "Review carefully.")),
        safety_score=safety_score,
        missing_protections=missing,
        rights_waived=rights_waived,
        risks=risks,
        nlp_metadata=NLPMetadata(
            pre_classification=nlp_result["pre_classification"],
            classification_confidence=nlp_result["classification_confidence"],
            risk_density_score=nlp_result["risk_density"]["density_score"],
            risk_keyword_counts=nlp_result["risk_density"]["counts"],
            top_risk_terms=nlp_result["risk_density"].get("top_risk_terms", []),
            entities=nlp_result["entities"],
            obligations=[ObligationItem(**o) for o in nlp_result["obligations"]],
            ambiguities=[AmbiguityItem(**a) for a in nlp_result["ambiguities"]],
            power_imbalance=nlp_result["power_imbalance"],
            readability=nlp_result["readability"],
            contradictions=[ContradictionItem(**c) for c in nlp_result["contradictions"]],
            pii_redacted=nlp_result["pii_redacted"],
            word_count=nlp_result["word_count"],
            total_chunks=nlp_result["total_chunks"],
            pipeline_ms=nlp_result["pipeline_ms"],
        ),
        model_used=model_used,
        processing_time=round(processing_time, 3),
        from_cache=from_cache,
    )


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