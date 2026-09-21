from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import time

app = FastAPI(title="Quizeers Real-time API Prototype")

class Event(BaseModel):
    id: int
    user_id: int
    score: float
    ts: Optional[float] = None

@app.get("/health")
async def health():
    return {"status": "ok", "ts": time.time()}

@app.post("/ingest")
async def ingest(event: Event):
    event.ts = event.ts or time.time()
    # In a real pipeline we'd publish this to Kafka/Redpanda or write to the high-velocity store
    return {"ingested": True, "event": event.dict()}

@app.get("/query")
async def query(limit: int = 10):
    # Prototype: return synthesized rows to simulate querying the real-time store
    rows = [
        {"id": i, "user_id": i % 5, "score": float((i * 7) % 100), "ts": time.time() - i * 60}
        for i in range(limit)
    ]
    return {"rows": rows}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
