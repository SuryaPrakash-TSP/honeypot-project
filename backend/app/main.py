from fastapi import FastAPI, Request, Form, Depends, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, text, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional
import asyncio
import json
import os
import pickle
import threading
import time
import webbrowser
import hashlib
from collections import defaultdict, deque
import joblib
import numpy as np
import pandas as pd
import pytz
from tensorflow import keras

# =========================
# Globals / App State
# =========================
Base = declarative_base()
IST = pytz.timezone("Asia/Kolkata")

connected_clients: List[WebSocket] = []
app_state: dict = {}
session_commands: Dict[str, List[str]] = {}

# PHASE 10: Adaptive Response Engine
rate_limiters: Dict[str, deque] = {}  # IP -> timestamps
bad_actors: Dict[str, dict] = {}      # IP -> escalation data
decoys_dir = Path("app/decoys")
decoys_dir.mkdir(exist_ok=True)

# Prevent NameError if LSTM assets are absent
lstm_model = None
lstm_tokenizer = None
lstm_label_encoder = None

# =========================
# Database Model
# =========================
class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ip = Column(String, nullable=False)
    username = Column(String, default="unknown")
    event_type = Column(String, nullable=False)
    command = Column(String)
    attack_class = Column(String, default="normal")
    severity = Column(String, default="LOW")
    timestamp = Column(DateTime, default=datetime.utcnow)

DATABASE_URL = "sqlite:///data/events.db"
engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def ensure_event_columns():
    from sqlalchemy import inspect
    insp = inspect(engine)
    if insp.has_table("events"):
        columns = insp.get_columns("events")
        col_names = [col["name"] for col in columns]
        with engine.begin() as conn:
            if "attack_class" not in col_names:
                conn.execute(text("ALTER TABLE events ADD COLUMN attack_class TEXT DEFAULT 'normal'"))
            if "severity" not in col_names:
                conn.execute(text("ALTER TABLE events ADD COLUMN severity TEXT DEFAULT 'LOW'"))

# =========================
# PHASE 10: Rate Limiter & Escalation
# =========================
class RateLimiter:
    def __init__(self, window: int = 60, max_requests: int = 5):
        self.window = window
        self.max_requests = max_requests
        self.requests: Dict[str, deque] = defaultdict(deque)

    async def is_allowed(self, ip: str) -> bool:
        now = time.time()
        window_requests = self.requests[ip]
        
        # Remove old requests
        while window_requests and now - window_requests[0] > self.window:
            window_requests.popleft()
        
        if len(window_requests) >= self.max_requests:
            return False
        
        window_requests.append(now)
        return True

    def get_stats(self, ip: str) -> dict:
        now = time.time()
        window_requests = self.requests[ip]
        recent = sum(1 for t in window_requests if now - t <= 60)
        return {"count_1m": recent, "blocked": len(window_requests) >= self.max_requests}

rate_limiter = RateLimiter()

def escalate_bad_actor(ip: str, event_data: dict):
    """Track persistent bad actors for deeper traps"""
    if ip not in bad_actors:
        bad_actors[ip] = {"events": 0, "high_severity": 0, "first_seen": time.time()}
    
    bad_actors[ip]["events"] += 1
    if event_data["severity"] == "HIGH":
        bad_actors[ip]["high_severity"] += 1
    
    # Escalate after 3+ high severity or 10+ events
    score = bad_actors[ip]["high_severity"] + (bad_actors[ip]["events"] // 3)
    return score >= 3

# =========================
# Time Helpers
# =========================
def get_ist_now():
    return datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(IST)

def format_time(ts):
    if isinstance(ts, str):
        try:
            raw = ts.rstrip("Z")
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = pytz.utc.localize(dt)
            dt = dt.astimezone(IST)
            return dt.strftime("%H:%M:%S")
        except Exception:
            return ts[-8:] if len(ts) >= 8 else "00:00:00"
    if hasattr(ts, "strftime"):
        dt = ts
        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)
        dt = dt.astimezone(IST)
        return dt.strftime("%H:%M:%S")
    return get_ist_now().strftime("%H:%M:%S")

# =========================
# Lifespan
# =========================
@asynccontextmanager
async def lifespan(app_: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_event_columns()

    # Load RF model
    rf_model_path = Path("app/honeypot_rf_v2.pkl")
    rf_metadata_path = Path("app/model_metadata.json")
    if rf_model_path.exists() and rf_metadata_path.exists():
        try:
            rf_model = joblib.load(rf_model_path)
            with open(rf_metadata_path, "r", encoding="utf-8") as f:
                rf_metadata = json.load(f)
            app_state["rf_model"] = rf_model
            app_state["rf_features"] = rf_metadata.get("features", ["ip_freq", "cmd_len", "sudo_flag", "wget_curl"])
            app_state["rf_info"] = {
                "version": rf_metadata.get("version", "RF v7.1"),
                "accuracy": float(rf_metadata.get("accuracy", 0.96)),
                "trained_samples": rf_metadata.get("trained_samples", 50000),
                "features": app_state["rf_features"],
                "model_size_kb": rf_metadata.get("model_size_kb", 48),
            }
            print(f"Loaded RF: {app_state['rf_info']['version']} | {app_state['rf_info']['accuracy']:.1%}")
        except Exception as e:
            app_state["rf_info"] = {}
            print(f"RF load failed: {e}")
    else:
        app_state["rf_info"] = {}

    # Load LSTM model
    global lstm_model, lstm_tokenizer, lstm_label_encoder
    lstm_model_path = Path("app/lstm_ssh_v8.keras")
    lstm_tokenizer_path = Path("app/lstm_tokenizer.pkl")
    lstm_encoder_path = Path("app/lstm_label_encoder.pkl")
    if all(p.exists() for p in [lstm_model_path, lstm_tokenizer_path, lstm_encoder_path]):
        try:
            lstm_model = keras.models.load_model(str(lstm_model_path))
            with open(lstm_tokenizer_path, "rb") as f:
                lstm_tokenizer = pickle.load(f)
            with open(lstm_encoder_path, "rb") as f:
                lstm_label_encoder = pickle.load(f)
            app_state["lstm_info"] = {
                "version": "LSTM v8.1",
                "accuracy": 0.979,
                "trained_samples": 233000,
                "classes": 9,
                "max_sequence_length": getattr(lstm_tokenizer, "max_length", 100),
            }
            print(f"Loaded LSTM: {app_state['lstm_info']['accuracy']:.1%}")
        except Exception as e:
            lstm_model = None
            lstm_tokenizer = None
            lstm_label_encoder = None
            app_state["lstm_info"] = {}
            print(f"LSTM load failed: {e}")
    else:
        app_state["lstm_info"] = {}

    app_state["hybrid_info"] = "Phase 10: Adaptive Response Active"
    print("PHASE 10 COMPLETE - Adaptive Response Engine LIVE")
    
    yield

# =========================
# App Initialization - FIXED ORDER
# =========================
app = FastAPI(title="Honeypot SOC - Phase 10", lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# PHASE 10: Decoy Files Mount
app.mount("/decoys", StaticFiles(directory="app/decoys"), name="decoys")

# =========================
# PHASE 10: WebSocket Manager (MOVED AFTER APP CREATION)
# =========================
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_alert(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast_alert(self, alert_data: dict):
        disconnected = []
        for connection in self.active_connections[:]:
            try:
                await connection.send_text(json.dumps(alert_data))
            except Exception:
                disconnected.append(connection)
        
        for connection in disconnected:
            self.active_connections.remove(connection)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# =========================
# ML Helpers (Enhanced)
# =========================
def get_ip_freq(db: Session, ip: str) -> float:
    result = db.execute(text("SELECT COUNT(*) FROM events WHERE source_ip = :ip"), {"ip": ip}).scalar()
    return float(result or 1.0)

def compute_ml_features(db: Session, ip: str, cmd: str, sudo_flag: int = 0) -> list:
    ip_freq = get_ip_freq(db, ip)
    cmd_len = float(len(cmd or ""))
    sudo_flag = float(sudo_flag)
    wget_curl = 1.0 if any(p in (cmd or "").lower() for p in ["wget", "curl"]) else 0.0
    rf_features = app_state.get("rf_features", ["ip_freq", "cmd_len", "sudo_flag", "wget_curl"])
    return [ip_freq, cmd_len, sudo_flag, wget_curl][:len(rf_features)]

def predict_rf(features: list) -> tuple[str, float]:
    rf_model = app_state.get("rf_model")
    if not rf_model:
        return "normal", 0.0
    rf_features = app_state.get("rf_features", ["ip_freq", "cmd_len", "sudo_flag", "wget_curl"])
    data_df = pd.DataFrame([features], columns=rf_features)
    pred_class = rf_model.predict(data_df)[0]
    proba = rf_model.predict_proba(data_df)[0]
    confidence = float(np.max(proba))
    attack_types = {0: "normal", 1: "brute-force", 2: "exploitation"}
    return attack_types.get(int(pred_class), "unknown"), confidence

def predict_lstm_session_commands(commands: list[str]) -> str:
    global lstm_model, lstm_tokenizer, lstm_label_encoder
    if not all([lstm_model, lstm_tokenizer, lstm_label_encoder]):
        return "lstm_unavailable"
    sequences = lstm_tokenizer.texts_to_sequences(commands)
    if not sequences:
        return "no_commands"
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    max_length = app_state.get("lstm_info", {}).get("max_sequence_length", 100)
    padded = pad_sequences(sequences, maxlen=max_length, padding="post", truncating="post")
    prediction = lstm_model.predict(padded, verbose=0)
    predicted_class_idx = int(np.argmax(prediction[0]))
    return str(lstm_label_encoder.inverse_transform([predicted_class_idx])[0])

def predict_hybrid(rf_class: str, rf_conf: float, lstm_threat: str, session_length: int) -> dict:
    weights = {"rf": 0.4, "lstm": 0.6}
    threat_score = (
        rf_conf * weights["rf"] * (1 if rf_class != "normal" else 0)
        + (weights["lstm"] * (1 if any(t in lstm_threat for t in ["Tactic", "Technique"]) else 0))
    )
    final_threat = "HIGH" if threat_score > 0.5 else "MEDIUM" if threat_score > 0.3 else "LOW"
    return {
        "rf_event": rf_class,
        "rf_confidence": rf_conf,
        "lstm_session": lstm_threat,
        "session_length": session_length,
        "hybrid_threat": final_threat,
        "threat_score": round(threat_score, 3),
        "fusion_method": "weighted_rf_lstm",
    }

def compute_severity(cmd: str, attack_class: str) -> str:
    cmd_l = (cmd or "").lower()
    high_patterns = ["wget", "nc", "rm -rf", "curl", "sudo"]
    if any(p in cmd_l for p in high_patterns) or attack_class == "exploitation":
        return "HIGH"
    if attack_class == "brute-force":
        return "MEDIUM"
    return "LOW"

# =========================
# PHASE 10: Routes
# =========================
@app.get("/")
async def root():
    db = SessionLocal()
    try:
        count = db.query(Event).count()
    finally:
        db.close()
    rf_info = app_state.get("rf_info", {})
    lstm_info = app_state.get("lstm_info", {})
    return {
        "status": "Phase 10 LIVE - Adaptive Response Engine",
        "events": count,
        "phase": "10",
        "models": {
            "rf": f"{rf_info.get('version', 'N/A')} | {rf_info.get('accuracy', 0):.1%}" if rf_info else "Disabled",
            "lstm": f"{lstm_info.get('version', 'N/A')} | {lstm_info.get('accuracy', 0):.1%}" if lstm_info else "Disabled",
        },
        "features": {
            "live_alerts": "WebSocket Active",
            "brute_force": "Rate Limiting Live", 
            "escalation": "Bad Actor Tracking",
            "decoys": "/decoys/ Mounted"
        }
    }

@app.get("/model-info")
async def model_info():
    rf_info = app_state.get("rf_info", {})
    lstm_info = app_state.get("lstm_info", {})
    return {
        "rf_model": rf_info,
        "lstm_model": lstm_info,
        "status": "Phase 10: Adaptive Response Active",
        "phase": "10",
        "rate_limiter_stats": dict(rate_limiter.requests),
        "bad_actors_count": len(bad_actors)
    }

@app.get("/decoys")
async def list_decoys():
    """List available decoy files for escalated actors"""
    files = [f.name for f in decoys_dir.glob("*") if f.is_file()]
    return {"decoys": files, "path": "/decoys/"}

# Create sample decoy files
def create_decoy_files():
    decoys = {
        "id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA... (fake key)",
        "malware.exe": "GIF89a... (harmless GIF disguised)",
        "rootkit.sh": "#!/bin/bash\necho 'Fake rootkit'\nexit 0",
    }
    for name, content in decoys.items():
        path = decoys_dir / name
        if not path.exists():
            path.write_text(content[:500])  # truncated safe content

@app.post("/ingest_ssh")
async def ingest_ssh(
    ip: str = Form(...),
    username: str = Form("unknown"),
    command: str = Form(...),
    session_id: str = Form("ssh"),
):
    # PHASE 10: Rate limiting check
    if not await rate_limiter.is_allowed(ip):
        alert_data = {
            "type": "alert",
            "severity": "HIGH",
            "title": "BRUTE FORCE BLOCKED",
            "message": f"IP {ip} exceeded rate limit (5+/min)",
            "action": "BLOCKED",
            "timestamp": get_ist_now().isoformat()
        }
        asyncio.create_task(manager.broadcast_alert(alert_data))
        raise HTTPException(status_code=429, detail="Rate limited")

    db = SessionLocal()
    try:
        sudo_flag = 1 if "sudo" in (command or "").lower() else 0
        features = compute_ml_features(db, ip, command, sudo_flag)
        rf_class, rf_conf = predict_rf(features)
        severity = compute_severity(command, rf_class)

        if session_id not in session_commands:
            session_commands[session_id] = []
        session_commands[session_id].append(command)
        if len(session_commands[session_id]) > 50:
            session_commands[session_id] = session_commands[session_id][-50:]

        event = Event(
            source_ip=ip,
            username=username,
            event_type="ssh",
            command=command,
            attack_class=rf_class,
            severity=severity,
            timestamp=datetime.utcnow(),
        )
        db.add(event)
        db.commit()

    finally:
        db.close()

    # PHASE 10: Live Alerts + Escalation
    now_ist = get_ist_now()
    event_data = {
        "type": "new_event",
        "event": {
            "ip": ip,
            "source_ip": ip,
            "type": "ssh",
            "event_type": "ssh",
            "time": now_ist.isoformat(),
            "timestamp_formatted": format_time(now_ist),
            "cmd": (command or "")[:50],
            "command": command or "",
            "severity": severity.lower(),
            "attack_class": rf_class,
            "rf_confidence": round(rf_conf, 3),
        },
    }
    
    # High severity → RED popup alert
    if severity == "HIGH":
        alert_data = {
            "type": "alert",
            "severity": "HIGH",
            "title": "HIGH SEVERITY THREAT",
            "message": f"Command: {command[:100]}",
            "ip": ip,
            "action": "ESCALATING" if escalate_bad_actor(ip, {"severity": severity}) else "MONITOR",
            "timestamp": now_ist.isoformat(),
            "sound": "alert"
        }
        asyncio.create_task(manager.broadcast_alert(alert_data))
    
    asyncio.create_task(manager.broadcast_alert(event_data))
    return {
        "status": "logged",
        "severity": severity,
        "rf_class": rf_class,
        "confidence": rf_conf,
        "rate_limited": False,
        "escalated": ip in bad_actors
    }

# Keep existing endpoints unchanged for compatibility
@app.post("/predict_lstm", response_model=dict)
async def predict_lstm_endpoint(request: dict):
    commands = request.get("commands", [])
    if not commands:
        raise HTTPException(status_code=400, detail="Commands list required")
    threat = predict_lstm_session_commands(commands)
    return {"threat": threat, "model": "LSTM v8.1", "input_length": len(commands), "status": "predicted"}

@app.post("/predict_hybrid", response_model=dict)
async def predict_hybrid_endpoint(request: dict):
    session_id = request.get("session_id", "default")
    current_command = request.get("command", "")
    db = SessionLocal()
    try:
        sudo_flag = 1 if "sudo" in (current_command or "").lower() else 0
        features = compute_ml_features(db, "0.0.0.0", current_command, sudo_flag)
        rf_class, rf_conf = predict_rf(features)
    finally:
        db.close()
    session_cmds = session_commands.get(session_id, []).copy()
    if current_command:
        session_cmds.append(current_command)
    lstm_threat = predict_lstm_session_commands(session_cmds[-20:])
    hybrid_result = predict_hybrid(rf_class, rf_conf, lstm_threat, len(session_cmds))
    return {**hybrid_result, "session_id": session_id, "model": "Hybrid RF v7.1 + LSTM v8.1"}

@app.get("/events")
async def events_api(db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(20).all()
    return [{
        "ip": e.source_ip,
        "type": e.event_type,
        "time": format_time(e.timestamp),
        "cmd": (getattr(e, "command", "N/A") or "N/A")[:50],
        "severity": getattr(e, "severity", "LOW"),
        "attack_class": getattr(e, "attack_class", "normal"),
    } for e in events]

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_view(request: Request, db: Session = Depends(get_db)):
    total = db.query(Event).count()
    web = db.query(Event).filter(Event.event_type == "web").count()
    ssh = db.query(Event).filter(Event.event_type == "ssh").count()
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(50).all()
    events_data = [{
        "timestamp_formatted": format_time(e.timestamp),
        "source_ip": e.source_ip,
        "event_type": e.event_type,
        "command": getattr(e, "command", "") or "",
        "severity": getattr(e, "severity", "LOW"),
        "attack_class": getattr(e, "attack_class", "normal"),
    } for e in events]
    
    rf_info = app_state.get("rf_info", {})
    lstm_info = app_state.get("lstm_info", {})
    hybrid_info = app_state.get("hybrid_info", "Phase 10: Adaptive Response Active")
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "events": events_data,
        "total_events": total,
        "web_count": web,
        "ssh_count": ssh,
        "rf_info": rf_info,
        "lstm_info": lstm_info,
        "hybrid_info": hybrid_info,
        "phase": "Phase 10 Complete - Adaptive Response LIVE",
    })

class PredictRequest(BaseModel):
    ip_freq: float
    cmd_len: float
    sudo_flag: int
    wget_curl: float

@app.post("/predict", response_model=dict)
async def predict_endpoint(req: PredictRequest):
    features = [req.ip_freq, req.cmd_len, float(req.sudo_flag), req.wget_curl]
    rf_class, confidence = predict_rf(features)
    attack_types = {0: "normal", 1: "brute-force", 2: "exploitation"}
    pred_class_id = next((k for k, v in attack_types.items() if v == rf_class), 0)
    return {
        "attack_type": rf_class,
        "confidence": confidence,
        "class_id": pred_class_id,
        "model": "RF v7.1",
    }

# Keep legacy broadcast for compatibility
async def broadcast_event(event_data: dict):
    await manager.broadcast_alert(event_data)

# =========================
# Browser Auto-Open
# =========================
def open_browser():
    time.sleep(8)
    url = "http://localhost:8000/dashboard"
    try:
        webbrowser.open_new(url)
        print(f"Dashboard: {url} (Phase 10 LIVE)")
    except Exception as e:
        print(f"Could not auto-open browser: {e}")
        print(f"Open manually: {url}")

# =========================
# Main Runner
# =========================
if __name__ == "__main__":
    create_decoy_files()  # PHASE 10: Create decoy files
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()
    
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
