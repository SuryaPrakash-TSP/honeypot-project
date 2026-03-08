from fastapi import FastAPI, Request, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.models.event import Base, Event
from datetime import datetime

# DB
DATABASE_URL = "sqlite:///../data/events.db"
engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="Honeypot v3 - Dashboard LIVE", version="0.3.0")
templates = Jinja2Templates(directory="app/templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

# Phase 3: Dashboard helper function
def get_recent_events(db: Session = Depends(get_db), limit: int = 20):
    return db.query(Event).order_by(Event.timestamp.desc()).limit(limit).all()

@app.get("/")
async def health():
    db = SessionLocal()
    event_count = db.query(Event).count()
    db.close()
    return {"status": "Phase 3 Dashboard LIVE ✅", "db": DATABASE_URL, "events": event_count}

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.client.host
    session_id = f"web_login_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    db = SessionLocal()
    event = Event()
    event.source_ip = client_ip
    event.username = username
    event.password = password
    event.command = f"web_login attempt"
    event.session_id = session_id
    event.event_type = "web"
    event.severity = "low"
    event.timestamp = datetime.now()
    db.add(event)
    db.commit()
    db.close()

    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/events")
async def list_events(db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(10).all()
    return {"events": [e.__dict__ for e in events]}

# PHASE 3 DASHBOARD ✅
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(20).all()
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "events": events,
        "total_events": len(events)
    })
