from typing import Optional
from api_models import AnalyzeResponse, RightWaived, RiskItem, NLPMetadata, ObligationItem, AmbiguityItem, ContradictionItem

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

