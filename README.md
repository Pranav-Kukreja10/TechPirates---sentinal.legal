# TechPirates---sentinal.legal

![Hackathon](https://img.shields.io/badge/Hackathon-Hack_Helix_2026-blueviolet?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-1.0+-00a67d?style=for-the-badge&logo=fastapi)
![Ollama](https://img.shields.io/badge/Local_AI-Llama_3.1-black?style=for-the-badge&logo=meta)

> **Official submission for Hack Helix 2026.** > Sentinal Legal Engine is a high-speed, privacy-first legal contract parsing system. It utilizes a custom 12-stage deep NLP pipeline combined with localized LLMs to instantly analyze contracts, detect power imbalances, flag high-risk clauses, and generate negotiation strategies—all while keeping sensitive data securely on your local machine.

---

Problem Statement: 
Legal Document Simplifier with Risk Surface Mapping
Contracts are written to protect the party with the lawyer. Build a system that takes an uploaded agreement
(rental, employment, loan, terms of service) and produces a plain-language summary alongside a risk surface
map - identifying clauses that are unusual, one-sided, or waive significant rights - ranked by potential user
impact.

## ✨ Key Features
* **12-Stage Deep NLP Pipeline:** Extracts obligations, ambiguities, and contradictions before the LLM even sees the text.
* **Local-First Architecture:** Zero data leaves your machine when running in local mode.
* **Dynamic Routing:** Automatically fails over to Groq cloud APIs if local inference times out or context limits are exceeded.
* **E2E Encrypted Cloud Mode:** Utilizes X25519 ECDH + AES-256-GCM for secure cloud processing.
* **Speed Optimized:** Implements response caching, dynamic token sizing, and persistent HTTP pools.

---

## 🏗️ Project Architecture
The engine is split into modular components for scalability:
* **`main.py`**: Core FastAPI application and endpoint routing.
* **`api_models.py`**: Pydantic schemas enforcing strict request/response validation.
* **`nlp.py`**: The custom 12-stage NLP text processing pipeline.
* **`llm_router.py`**: Intelligent routing between Local Llama 3.1 and Cloud Groq models.
* **`crypto.py`**: E2E encryption implementation for secure cloud payloads.
* **`audit.py` & `rate_limit.py`**: Telemetry, latency tracking, and endpoint protection.
* **`index.html` & `update_*.py`**: Vanilla frontend UI and dynamic state managers.

---

## 🛠️ Prerequisites
* **Python:** 3.10 or higher.
* **Ollama:** Installed and running locally.
* **Git:** For cloning the repository.

---

## ⚙️ Installation & Setup

### 1. Clone & Install Dependencies
```bash
git clone [https://github.com/your-username/sentinal-legal-engine.git](https://github.com/your-username/sentinal-legal-engine.git)
cd sentinal-legal-engine

# Create and activate virtual environment
python -m venv .venv
# On Windows: .venv\Scripts\activate
# On Mac/Linux: source .venv/bin/activate

# Install required packages
pip install -r requirements.txt

uvicorn main:app --reload --host 127.0.0.1 --port 8000

ollama pull llama3.1:8b
ollama create sentinal-llama -f ./ModelFile
