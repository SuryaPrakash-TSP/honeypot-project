from fastapi import FastAPI, Request, Form, Depends, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from app.models.event import Base, Event  # ← now importing Base properly
from datetime import datetime
import pytz
from pathlib import Path
from contextlib import asynccontextmanager
import asyncio
import json

IST = pytz.timezone('Asia/Kolkata')
connected_clients: list[WebSocket] = []
app_state = {}

DATABASE_URL = "sqlite:///data/events.db"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)

# ✅ Create events table at startup
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="Honeypot SOC")
templates = Jinja2Templates(directory="app/templates")

def get_ist_now():
    utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)
    return utc_now.astimezone(IST)

def format_time(ts):
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

async def broadcast_event(event_data: dict):
    """Broadcast full event to dashboard"""
    disconnected = []
    for client in connected_clients:
        try:
            await client.send_text(json.dumps(event_data))
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
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

@app.get("/")
async def root():
    db = SessionLocal()
    count = db.query(Event).count()
    db.close()
    return {
        "status": "Phase 7 CLEAN - Backend Ready", 
        "events": count, 
        "mode": "RULES_ONLY",
        "next": "Phase 7.1: Download 50K+ dataset + RF retrain"
    }

@app.get("/login", response_class=HTMLResponse)
async def login_trap(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def trap_login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host
    db = SessionLocal()

    severity = "LOW"
    attack_class = "normal"

    event = Event(
        source_ip=ip,
        username=username,
        password=password,
        event_type="web",
        command=f"login_attempt:{username}:{password}",
        attack_class=attack_class,
        severity=severity,
        timestamp=get_ist_now()
    )
    db.add(event)
    db.commit()
    db.close()

    event_data = {
        "type": "new_event",
        "event": {
            "ip": ip,
            "type": "web",
            "time": format_time(get_ist_now()),
            "cmd": event.command[:50],
            "severity": severity,
            "attack_class": attack_class
        }
    }
    asyncio.create_task(broadcast_event(event_data))
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login/json")
async def login_json_trap(request: Request):
    ip = request.client.host
    try:
        body = await request.body()
        data = json.loads(body)
        username = data.get("username", "unknown")
        password = data.get("password", "unknown")
    except:
        username, password = "malformed", "malformed"

    db = SessionLocal()
    severity = "LOW"
    attack_class = "normal"

    event = Event(
        source_ip=ip,
        username=username,
        password=password,
        event_type="web",
        command=f"json_login_attempt:{username}",
        attack_class=attack_class,
        severity=severity,
        timestamp=get_ist_now()
    )
    db.add(event)
    db.commit()
    db.close()

    event_data = {
        "type": "new_event",
        "event": {
            "ip": ip,
            "type": "web",
            "time": format_time(get_ist_now()),
            "cmd": event.command[:50],
            "severity": severity,
            "attack_class": attack_class
        }
    }
    asyncio.create_task(broadcast_event(event_data))

    return {"status": "logged", "attack_class": attack_class}

@app.post("/ingest_ssh")
async def ingest_ssh(ip: str = Form(...), username: str = Form("unknown"), command: str = Form(...), session_id: str = Form("ssh")):
    db = SessionLocal()
    severity = "LOW"
    
    event = Event(
        source_ip=ip,
        username=username,
        event_type="ssh",
        command=command,
        severity=severity,
        attack_class="normal",
        timestamp=get_ist_now()
    )
    db.add(event)
    db.commit()
    db.close()
    
    event_data = {
        "type": "new_event",
        "event": {
            "ip": ip,
            "type": "ssh",
            "time": format_time(get_ist_now()),
            "cmd": command[:50],
            "severity": severity,
            "attack_class": "normal"
        }
    }
    asyncio.create_task(broadcast_event(event_data))
    
    return {"status": "logged", "severity": severity, "attack_class": "normal"}

@app.get("/events")
async def events_api(db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(20).all()
    return [
        {
            "ip": e.source_ip,
            "type": e.event_type,
            "time": format_time(e.timestamp),
            "cmd": getattr(e, "command", "N/A")[:50],
            "severity": getattr(e, "severity", "LOW"),
            "attack_class": getattr(e, "attack_class", "N/A")
        }
        for e in events
    ]

@app.get("/events.csv")
async def export_csv(db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).all()
    import csv
    from io import StringIO
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "Type", "Time(IST)", "Command", "Severity", "Attack Class"])
    for e in events:
        writer.writerow([
            e.source_ip, e.event_type, format_time(e.timestamp), 
            getattr(e, "command", "N/A"), getattr(e, "severity", "LOW"), getattr(e, "attack_class", "N/A")
        ])
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
    events_data = [
        {
            "timestamp_formatted": format_time(e.timestamp),
            "source_ip": e.source_ip,
            "event_type": e.event_type,
            "command": getattr(e, "command", "N/A"),
            "severity": getattr(e, "severity", "LOW"),
            "attack_class": getattr(e, "attack_class", "N/A")
        }
        for e in events
    ]

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "events": events_data,
            "total_events": total,
            "web_count": web,
            "ssh_count": ssh,
            "mode": app_state.get("mode", "RULES_ONLY")
        }
    )

@app.post("/backfill_ml")
async def backfill_ml_events(background_tasks: BackgroundTasks):
    return {"status": "disabled_phase7", "message": "Phase 7.1 ML retrain first"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
