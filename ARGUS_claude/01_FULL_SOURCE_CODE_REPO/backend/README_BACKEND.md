# Project Argus Local Demo Server

False-positive feedback is accepted at `POST /feedback/false-positive` and stored locally in `backend/data/false_positive_reports.jsonl`. View the report count at `GET /feedback/stats`. The collector stores decision metadata only and is not a public telemetry service.

This FastAPI server is optional. It does not call any external AI API. The Chrome extension and its versioned JavaScript evidence engine are the authoritative detector; `/analyze` is retained only as a local compatibility endpoint.

Use it when you want an easy local URL for the demo test pages:

```powershell
cd Desktop/Project-Argus-Extension/backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Endpoints

- `GET /health` returns the local model status.
- `POST /analyze` returns a local Project Argus model result from metadata only.
- `GET /test-site/fake-store.html` and the other `/test-site/...` pages serve the local demo pages.

## Privacy

The server does not need an API key. It does not receive typed passwords, OTP values, cookies, tokens, localStorage, sessionStorage, request bodies, response bodies, or request headers.
