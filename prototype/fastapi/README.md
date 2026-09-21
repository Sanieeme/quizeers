FastAPI prototype for the Quizeers real-time API

Run locally:

```bash
python -m pip install -r requirements.txt
python app.py
```

Or with uvicorn directly:

```bash
uvicorn app:app --reload --port 8000
```

Endpoints:
- `GET /health` — simple health check
- `POST /ingest` — accept an event JSON (id, user_id, score, optional ts)
- `GET /query?limit=10` — returns synthetic rows to simulate the high-velocity store

Docker build:

```bash
docker build -t quizeers-fastapi .
docker run -p 8000:8000 quizeers-fastapi
```
