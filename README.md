# Senior Citizen Digital Safety Companion (backend)

FastAPI service for user-submitted message analysis. It never connects to inboxes, scans in the background, or visits submitted URLs. No submitted content is persisted; logs exclude message text by default.

## Setup and run

Python 3.10+ is recommended. From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --host 0.0.0.0 --port 8000
```

API base: `http://127.0.0.1:8000`; interactive API docs: `/docs`; health: `/health`. The backend intentionally does not serve a frontend. Set `CORS_ORIGINS` to the separately hosted frontend origins.

## Deploy on Render

This repository is a backend only. In Render, create a **Blueprint** from the repository and use `render.yaml`. The log you shared shows the service is currently using `uvicorn main:app --reload`; update that service's **Settings → Build & Deploy → Start Command** to the production command below, or deploy the repository as a Blueprint so Render reads `render.yaml`:

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`

After the service deploys, its API will be available at `https://<service-name>.onrender.com`. `render.yaml` allows `https://frontend-m6mogfnwm-swayamshetkars-projects.vercel.app` and `https://frontend-five-chi-82.vercel.app`. If the Render service already has a manually configured `CORS_ORIGINS` environment variable, update it to those exact origins (scheme and hostname, no path or trailing slash), separated by commas, then redeploy. For local development, the default localhost origins remain enabled.

Render's `PORT` is supplied automatically and the service binds to `0.0.0.0`. Add `AI_PROVIDER` and `AI_API_KEY` as Render environment variables only if you want AI analysis; rules-only mode works without a key. Never commit `.env` or place provider keys in frontend configuration.

## AI configuration and privacy

Rules-only analysis is the default and needs no key. To enable AI, set `AI_PROVIDER=openai` or `google`, `AI_API_KEY` and `AI_MODEL` in an untracked `.env`. The selected provider receives the submitted message for semantic analysis. AI output is JSON parsed into a strict Pydantic model; timeouts, malformed responses, and provider failures fall back to deterministic rules and are reported as `FALLBACK`. API keys stay server-side. Never put secrets in frontend code. `LOG_MESSAGES=false` is the safe default.

## Request

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze/message \
  -H 'Content-Type: application/json' \
  -d '{"message":"Your account will be blocked today. Tell me your OTP.","claimed_organization":"HDFC Bank"}'
```

Response contains `risk_score` (0–100), `risk_level`, evidence-backed `signals`, recommendations, limitations, and `ai_status`. Scores use centralized weights, count a URL finding only at its strongest matched URL signal, and cap at 100: LOW 0–29, MEDIUM 30–59, HIGH 60–100. AI and rules detecting one code is corroboration but does not add score. A LOW score is not a guarantee of safety.

## Tests

```bash
pytest -q
python tests/evaluate.py
```

## Limitations

Rules are transparent heuristics, not identity or intent verification. The small organization-domain map can be incomplete; third-party campaign domains can cause mismatches. URL analysis is passive and does not determine destination reputation or follow redirects. Rules-only mode can miss subtle context; AI output may also be wrong. The bundled synthetic smoke dataset is tiny and is not representative; its metrics are diagnostic only. This project has not undergone a security audit.
