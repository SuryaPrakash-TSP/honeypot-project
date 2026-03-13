from fastapi import FastAPI, Request, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.models.event import Base, Event
from datetime import datetime
from pathlib import Path
from contextlib import asynccontextmanager

app_state = {}

@asynccontextmanager
async def lifespan(app_: FastAPI):
    """Application lifespan events"""
    model_path = Path.cwd() / "honeypot_rf_model.pkl"
    try:
        import numpy as np
        import joblib
        app_state["model"] = joblib.load(model_path)
        app_state["mode"] = "ML"
    except:
        app_state["model"] = None
        app_state["mode"] = "RULES"
    yield
    app_state.clear()

# Database
DATABASE_URL = "sqlite:///data/events.db"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="Honeypot SOC", version="0.7.0", lifespan=lifespan)  # v0.7.0
templates = Jinja2Templates(directory="app/templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

Base.metadata.create_all(bind=engine)

@app.get("/")
async def root():
    """Health check"""
    db = SessionLocal()
    count = db.query(Event).count()
    db.close()
    return {
        "status": "Phase 3-7 LIVE ✅",  # Updated
        "mode": app_state.get("mode", "RULES"),
        "model": app_state.get("model") is not None,
        "events": count,
        "db": DATABASE_URL
    }

@app.get("/login", response_class=HTMLResponse)
async def login_trap(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def trap_login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host
    session_id = f"web_login_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    db = SessionLocal()
    event = Event(
        source_ip=ip,
        username=username,
        password=password,
        event_type="web",
        command="web_login_attempt",
        session_id=session_id,
        severity="low",
        timestamp=datetime.now()
    )
    db.add(event)
    db.commit()
    db.close()

    return templates.TemplateResponse("login.html", {"request": request})

# NEW: Phase 6 - SSH Event Ingestion to DB TABLE
@app.post("/ingest_ssh")
async def ingest_ssh(
    ip: str = Form(...),
    username: str = Form("unknown"),
    command: str = Form(...),
    session_id: str = Form("ssh_session")
):
    """Log Cowrie SSH to DB → shows in dashboard table!"""
    db = SessionLocal()
    event = Event(
        source_ip=ip,
        username=username,
        password="N/A",
        event_type="ssh",
        command=command,
        session_id=session_id,
        severity="medium" if any(x in command.lower() for x in ["sudo", "passwd"]) else "low",
        timestamp=datetime.now()
    )
    db.add(event)
    db.commit()
    db.close()
    return {"status": "SSH logged to DB", "command": command[:50]}

@app.get("/events")
async def events(db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(10).all()
    return {"events": [e.__dict__ for e in events]}

@app.get("/ssh")
async def ssh_info():
    """Cowrie SSH status"""
    cowrie_path = Path.cwd().parent / "cowrie-parsed.txt"
    base_count = 14
    parsed_count = 0
    if cowrie_path.exists():
        parsed_count = sum(1 for line in cowrie_path.open() if line.strip())
    return {
        "ssh_sessions": base_count + parsed_count,
        "status": "active",
        "port": 2222
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_view(request: Request, db: Session = Depends(get_db)):
    # OPTIMIZED: Count queries instead of loading all
    total_events = db.query(Event).count()
    web_count = db.query(Event).filter(Event.event_type == "web").count()
    ssh_count_db = db.query(Event).filter(Event.event_type == "ssh").count()

    # Table: Recent 50 (performance)
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(50).all()

    # File-based SSH (legacy)
    cowrie_path = Path.cwd().parent / "cowrie-parsed.txt"
    ssh_file_count = 14
    if cowrie_path.exists():
        try:
            ssh_file_count += len([l for l in cowrie_path.read_text().splitlines() if l.strip()])
        except:
            pass

    total_ssh = ssh_count_db + ssh_file_count  # DB + File
    threat_level = "LOW" if total_events < 20 else "MEDIUM" if total_events < 100 else "HIGH"

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "events": events,
        "total_events": total_events,
        "web_count": web_count,
        "ssh_count": total_ssh,  # Combined!
        "threat_level": threat_level,
        "mode": app_state.get("mode", "RULES")
    })

class ThreatRequest(BaseModel):
    username: str
    password: str = ""
    command: str = ""

@app.post("/predict")
async def predict_threat(req: ThreatRequest):
    """Phase 7: ML Threat Scoring - FIXED defaults"""
    model = app_state.get("model")
    mode = app_state.get("mode", "RULES")

    if model and mode == "ML":
        try:
            import numpy as np
            feats = np.array([[len(req.username), len(req.password), len(req.command or ""),
                              int(any(x in req.username.lower() for x in ["admin", "root"])),
                              int(len(req.password) < 6 if req.password else False),
                              int(any(x in (req.command or "").lower() for x in ["whoami", "sudo", "passwd"]))]])
            pred = model.predict(feats)[0]
            prob = model.predict_proba(feats).max()
            return {"threat_level": "high" if pred else "low", "confidence": float(prob), "mode": mode}
        except:
            pass  # Fallback

    # Rules fallback
    score = 0.0
    if any(x in req.username.lower() for x in ["admin", "root"]): score += 0.3
    if req.password and (len(req.password) < 6 or req.password.lower() in ["password", "123456", "123"]): score += 0.3
    if req.command and any(x in req.command.lower() for x in ["whoami", "sudo", "passwd"]): score += 0.4
    level = "high" if score >= 0.6 else "medium" if score >= 0.3 else "low"

    return {"threat_level": level, "confidence": round(score, 2), "mode": mode}
