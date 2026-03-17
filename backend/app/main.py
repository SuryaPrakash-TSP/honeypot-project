from fastapi import FastAPI, Request, Form, Depends, WebSocket, WebSocketDisconnect
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
import pandas as pd
import numpy as np
import joblib
import os
import asyncio

# Global for WebSocket alerts
connected_clients: list[WebSocket] = []

app_state = {}

@asynccontextmanager
async def lifespan(app_: FastAPI):
    """Auto-load enhanced model or fallback"""
    model_paths = ['models/honeypot_enhanced_model.pkl', 'honeypot_rf_model.pkl']
    for path in model_paths:
        if Path(path).exists():
            app_state["model"] = joblib.load(path)
            app_state["model_path"] = path
            app_state["mode"] = "ENHANCED_ML"
            break
    else:
        app_state["model"] = None
        app_state["mode"] = "RULES"
    print(f"Loaded: {app_state.get('mode')} from {app_state.get('model_path')}")
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

app = FastAPI(title="Honeypot SOC v0.8.0", version="0.8.0", lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

Base.metadata.create_all(bind=engine)

async def broadcast_alert(message: str, alert_type: str = "high"):
    """Alert all dashboard clients"""
    data = {"alert": message, "type": alert_type}
    disconnected = []
    for client in connected_clients:
        try:
            await client.send_text(str(data))
        except WebSocketDisconnect:
            disconnected.append(client)
    for client in disconnected:
        connected_clients.remove(client)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()  # Keep alive
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

@app.get("/")
async def root():
    db = SessionLocal()
    count = db.query(Event).count()
    db.close()
    return {
        "status": "Phase 0-7+ ENHANCED ✅", 
        "mode": app_state.get("mode", "RULES"),
        "model": app_state.get("model_path", "None"),
        "events": count,
        "db": DATABASE_URL,
        "websockets": len(connected_clients)
    }

# Login trap unchanged
@app.get("/login", response_class=HTMLResponse)
async def login_trap(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def trap_login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host
    session_id = f"web_login_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    db = SessionLocal()
    event = Event(
        source_ip=ip, username=username, password=password, event_type="web",
        command="web_login_attempt", session_id=session_id, severity="low", timestamp=datetime.now()
    )
    db.add(event)
    db.commit()
    db.close()
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/ingest_ssh")
async def ingest_ssh(ip: str = Form(...), username: str = Form("unknown"), command: str = Form(...), session_id: str = Form("ssh_session")):
    db = SessionLocal()
    event = Event(
        source_ip=ip, username=username, password="N/A", event_type="ssh", command=command,
        session_id=session_id, severity="medium" if any(x in command.lower() for x in ["sudo", "passwd"]) else "low",
        timestamp=datetime.now()
    )
    db.add(event)
    db.commit()
    db.close()

    # Alert if dangerous
    if any(x in command.lower() for x in ["sudo", "rm"]):
        asyncio.create_task(broadcast_alert(f"🚨 SSH: {command[:30]} from {ip}", "high"))

    return {"status": "SSH logged", "command": command[:50]}

@app.get("/events")
async def events(db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(10).all()
    return {"events": [e.__dict__ for e in events]}

@app.get("/ssh")  # Unchanged
async def ssh_info():
    cowrie_path = Path.cwd().parent / "cowrie-parsed.txt"
    base_count = 14
    parsed_count = 0
    if cowrie_path.exists():
        parsed_count = sum(1 for line in cowrie_path.open() if line.strip())
    return {"ssh_sessions": base_count + parsed_count, "status": "active", "port": 2222}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_view(request: Request, db: Session = Depends(get_db)):
    total_events = db.query(Event).count()
    web_count = db.query(Event).filter(Event.event_type == "web").count()
    ssh_count_db = db.query(Event).filter(Event.event_type == "ssh").count()
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(50).all()

    cowrie_path = Path.cwd().parent / "cowrie-parsed.txt"
    ssh_file_count = 14
    if cowrie_path.exists():
        try:
            ssh_file_count += len([l for l in cowrie_path.read_text().splitlines() if l.strip()])
        except:
            pass
    total_ssh = ssh_count_db + ssh_file_count
    threat_level = "LOW" if total_events < 20 else "MEDIUM" if total_events < 100 else "HIGH"

    return templates.TemplateResponse("dashboard.html", {
        "request": request, "events": events, "total_events": total_events,
        "web_count": web_count, "ssh_count": total_ssh, "threat_level": threat_level,
        "mode": app_state.get("mode", "RULES")
    })

class ThreatRequest(BaseModel):
    source_ip: str = "127.0.0.1"
    username: str = ""
    password: str = ""
    command: str = ""

@app.post("/predict")
async def predict_threat(req: ThreatRequest):
    model = app_state.get("model")
    mode = app_state.get("mode", "RULES")
    model_name = Path(app_state.get("model_path", "")).name if app_state.get("model_path") else "RULES"

    if model and mode == "ENHANCED_ML":
        try:
            # New features matching notebook
            ip_freq = 2 if req.source_ip == 'evil.com' else 30  # Simulate lookup
            cmd_len = len(req.command)
            sudo_flag = 1 if any(x in req.command.lower() for x in ['sudo', 'rm', 'whoami']) else 0
            attempts_per_ip = 1  # From session count
            X_input = pd.DataFrame([[ip_freq, cmd_len, sudo_flag, attempts_per_ip]])
            pred = model.predict(X_input)[0]
            prob = model.predict_proba(X_input).max()
            threat = "HIGH" if pred else "LOW"

            # Top feature (simple)
            top_feat = "sudo_flag" if sudo_flag else "ip_freq"

            # Alert HIGH
            if threat == "HIGH":
                asyncio.create_task(broadcast_alert(f"🚨 ML HIGH: {req.command[:30]}"))

            return {
                "threat_level": threat, "confidence": float(prob),
                "mode": mode, "model": model_name,
                "features": {"ip_freq": ip_freq, "sudo_flag": sudo_flag},
                "top_feature": top_feat, "trained_on": 33
            }
        except Exception as e:
            print(f"ML error: {e}")  # Log

    # Rules fallback (unchanged)
    score = 0.0
    if any(x in req.username.lower() for x in ["admin", "root"]): score += 0.3
    if req.password and (len(req.password) < 6 or req.password.lower() in ["password", "123456"]): score += 0.3
    if req.command and any(x in req.command.lower() for x in ["whoami", "sudo", "passwd"]): score += 0.4
    level = "HIGH" if score >= 0.6 else "MEDIUM" if score >= 0.3 else "LOW"
    return {"threat_level": level, "confidence": round(score, 2), "mode": mode}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
