from fastapi import FastAPI, Request, Form, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.models.event import Base, Event
from datetime import datetime
import pytz  # pip install pytz
from pathlib import Path
from contextlib import asynccontextmanager
import pandas as pd
import numpy as np
import joblib
import os
import asyncio

# ✅ FORCE IST (ignores system clock)
IST = pytz.timezone('Asia/Kolkata')

connected_clients: list[WebSocket] = []
app_state = {}

@asynccontextmanager
async def lifespan(app_: FastAPI):
    model_paths = ['models/honeypot_enhanced_model.pkl', 'honeypot_rf_model.pkl']
    for path in model_paths:
        if Path(path).exists():
            model = joblib.load(path)
            app_state["model"] = model
            app_state["mode"] = "ENHANCED_ML"
            print(f"✅ Loaded ENHANCED_ML from {path}")
            break
    yield

# Database
DATABASE_URL = "sqlite:///data/events.db"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

app = FastAPI(title="Honeypot SOC", lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")

# ✅ FORCE IST TIMESTAMP (SYSTEM CLOCK PROOF)
def get_ist_now():
    """Always returns CURRENT IST time"""
    utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)
    return utc_now.astimezone(IST)

def format_time(ts):
    """Convert ANY time to IST HH:MM:%S"""
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.rstrip('Z')).astimezone(IST)
        except:
            return ts[-8:] if len(ts) >= 8 else "00:00:00"
    elif hasattr(ts, 'strftime'):
        dt = ts if ts.tzinfo else IST.localize(ts)
        dt = dt.astimezone(IST)
    else:
        dt = get_ist_now()
    return dt.strftime('%H:%M:%S')

templates.env.filters['format_time'] = format_time

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
Base.metadata.create_all(bind=engine)

async def broadcast_alert(message: str):
    data = {"alert": message}
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
        while True: await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

@app.get("/")
async def root():
    db = SessionLocal()
    count = db.query(Event).count()
    db.close()
    return {"status": "✅ LIVE", "events": count, "mode": app_state.get("mode", "RULES")}

@app.get("/login", response_class=HTMLResponse)
async def login_trap(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def trap_login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host
    db = SessionLocal()
    event = Event(
        source_ip=ip, username=username, password=password,
        event_type="web", command="login_attempt", severity="low",
        timestamp=get_ist_now()  # ✅ CURRENT IST
    )
    db.add(event)
    db.commit()
    db.close()
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/ingest_ssh")
async def ingest_ssh(ip: str = Form(...), username: str = Form("unknown"), command: str = Form(...), session_id: str = Form("ssh")):
    db = SessionLocal()
    severity = "high" if any(x in command.lower() for x in ["sudo", "rm"]) else "low"
    event = Event(
        source_ip=ip, username=username, event_type="ssh",
        command=command, severity=severity, timestamp=get_ist_now()
    )
    db.add(event)
    db.commit()
    db.close()

    if severity == "high":
        asyncio.create_task(broadcast_alert(f"🚨 {command[:30]} from {ip}"))

    return {"status": "logged", "severity": severity}

@app.get("/events")
async def events_api(db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(20).all()
    return [{"ip": e.source_ip, "type": e.event_type, "time": format_time(e.timestamp), 
             "cmd": e.command[:50], "severity": e.severity} for e in events]

@app.get("/events.csv")
async def export_csv(db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).all()
    import csv
    from io import StringIO
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "Type", "Time(IST)", "Command", "Severity"])
    for e in events:
        writer.writerow([e.source_ip, e.event_type, format_time(e.timestamp), e.command, e.severity])
    return HTMLResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=attacks.csv"}
    )

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_view(request: Request, db: Session = Depends(get_db)):
    total = db.query(Event).count()
    web = db.query(Event).filter(Event.event_type == "web").count()
    ssh = db.query(Event).filter(Event.event_type == "ssh").count()

    events = db.query(Event).order_by(Event.timestamp.desc()).limit(50).all()
    events_data = [{
        'timestamp_formatted': format_time(e.timestamp),
        'source_ip': e.source_ip,
        'event_type': e.event_type,
        'command': getattr(e, 'command', 'N/A'),
        'severity': e.severity
    } for e in events]

    return templates.TemplateResponse("dashboard.html", {
        "request": request, "events": events_data,
        "total_events": total, "web_count": web, "ssh_count": ssh,
        "mode": app_state.get("mode", "RULES")
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
