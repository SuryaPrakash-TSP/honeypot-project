from fastapi import FastAPI, Request, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.models.event import Base, Event
from datetime import datetime
import logging

# SSH Router - CORRECT import
from app.routers.events import router as api_router

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database
DATABASE_URL = "sqlite:///./events.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# App
app = FastAPI(title="Honeypot Dashboard v0.4.0")
templates = Jinja2Templates(directory="app/templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Router FIRST
app.include_router(api_router, prefix="/api", tags=["honeypot"])

Base.metadata.create_all(bind=engine)

@app.get("/")
async def health(db: Session = Depends(get_db)):
    count = db.query(Event).count()
    return {"status": "Phase 4 LIVE", "version": "0.4.0", "web_events": count}

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    ip = request.client.host
    session = f"web_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    db = SessionLocal()
    event = Event(
        source_ip=ip,
        username=username,
        password=password,
        command="web_login",
        session_id=session,
        event_type="web",
        severity="low",
        timestamp=datetime.now()
    )
    db.add(event)
    db.commit()
    logger.info(f"Web trap: {ip} {username}:{password[:3]}***")
    db.close()

    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/events")
async def list_events(limit: int = 10, db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(limit).all()
    return {"web_events": [e.__dict__ for e in events]}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(20).all()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "events": events,
        "total": len(events)
    })
