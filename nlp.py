import re, time, unicodedata
from collections import defaultdict

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

