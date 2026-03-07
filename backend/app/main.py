from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Honeypot Backend v1", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def health():
    return {"status": "Phase 1 Backend Ready", "version": "0.1.0"}

@app.get("/events")
async def list_events():
    return {"events": [], "message": "Phase 1 ingest ready"}
