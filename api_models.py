from pydantic import BaseModel, Field

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

class TranslateRequest(BaseModel):
    report: dict
    target_language: str = Field("hi", pattern="^(en|hi)$")
    mode: str = Field("local", pattern="^(local|cloud)$")
