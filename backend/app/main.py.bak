from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.event import Base

# Simple SQLite (sync)
DATABASE_URL = "sqlite:///../data/events.db"
engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="Honeypot Backend v1", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables on startup
Base.metadata.create_all(bind=engine)

@app.get("/")
async def health():
    return {"status": "Phase 1 Backend + DB Ready", "db": DATABASE_URL}

@app.get("/events")
async def list_events():
    return {"events": [], "message": "Event storage ready"}
