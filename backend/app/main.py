from fastapi import FastAPI, Request, Form, Depends, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import create_engine, text, Column, Text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from app.models.event import Base as OriginalBase, Event
from datetime import datetime
import pytz
from pathlib import Path
from contextlib import asynccontextmanager
import pandas as pd
import numpy as np
import joblib
import os
import asyncio
import json

IST = pytz.timezone("Asia/Kolkata")
connected_clients: list[WebSocket] = []
app_state = {}


# Extend Event table schema at startup if needed
def ensure_event_columns() -> None:
    from sqlalchemy import inspect
    insp = inspect(engine)
    if insp.has_table("events"):
        columns = [col["name"] for col in insp.get_columns("events")]

        if "attack_class" not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE events ADD COLUMN attack_class TEXT"))
                conn.commit()
                print("Added attack_class column to events")

        if "severity" not in columns:
            with engine.connect() as conn:
                conn.execute(
                    text("ALTER TABLE events ADD COLUMN severity TEXT DEFAULT 'LOW'")
                )
                conn.commit()
                print("Added severity column to events")


@asynccontextmanager
async def lifespan(app_: FastAPI):
    ensure_event_columns()

    # Load honeypot_rf_v2.pkl (Phase 7 96% RF model)
    model_path = "app/honeypot_rf_v2.pkl"
    if Path(model_path).exists():
        model = joblib.load(model_path)
        app_state["model"] = model
        app_state["mode"] = "PHASE7_RF_V2"
        app_state["model_info"] = {
            "name": "honeypot_rf_v2",
            "accuracy": "96%",
            "top_features": ["cmd_len", "sudo_flag", "wget_curl", "ip_freq"],
            "target_classes": ["normal", "attack"],
        }
        print(f"Loaded model {model_path} ({app_state['mode']})")
    else:
        print(f"Model not found at {model_path}; running in RULES mode")

    yield


DATABASE_URL = "sqlite:///data/events.db"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


app = FastAPI(title="Honeypot SOC", lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")


def get_ist_now() -> datetime:
    utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)
    return utc_now.astimezone(IST)


def format_time(ts):
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.rstrip("Z")).astimezone(IST)
        except Exception:
            return ts[-8:] if len(ts) >= 8 else "00:00:00"
    elif hasattr(ts, "strftime"):
        dt = ts if ts.tzinfo else IST.localize(ts)
        dt = dt.astimezone(IST)
    else:
        dt = get_ist_now()
    return dt.strftime("%H:%M:%S")


templates.env.filters["format_time"] = format_time


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_ip_freq(db: Session, ip: str) -> float:
    result = db.execute(
        text("SELECT COUNT(*) FROM events WHERE source_ip = :ip"), {"ip": ip}
    ).scalar()
    return float(result or 1.0)


def compute_ml_features_v2(
    db: Session, ip: str, cmd: str, sudo_flag: int = 0, wget_curl: int = 0
) -> list:
    """
    Phase 7 production features:
        cmd_len, sudo_flag, wget_curl, ip_freq
    """
    ip_freq = get_ip_freq(db, ip)
    cmd_len = float(len(cmd))
    return [cmd_len, sudo_flag, wget_curl, ip_freq]


def predict_attack_v2(model, features: list) -> tuple:
    """
    Predict and return class + confidence.
    """
    data_df = pd.DataFrame(
        [features],
        columns=["cmd_len", "sudo_flag", "wget_curl", "ip_freq"],
    )
    pred_class = model.predict(data_df)[0]
    proba = model.predict_proba(data_df)[0]
    confidence = float(np.max(proba))
    attack_types = {0: "normal", 1: "attack"}
    attack_class = attack_types.get(int(pred_class), "unknown")
    return attack_class, confidence


def compute_severity_v2(cmd: str, attack_class: str) -> str:
    """
    Severity logic: ML + command patterns.
    """
    high_patterns = ["wget", "nc", "rm -rf", "curl.*http", "sudo", "tftp"]
    if any(p in cmd.lower() for p in high_patterns) or attack_class == "attack":
        return "HIGH"
    return "LOW"


async def broadcast_event(event_data: dict):
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
    if websocket not in connected_clients:
        connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)


@app.get("/")
async def root():
    db = SessionLocal()
    count = db.query(Event).count()
    db.close()
    return {
        "status": "LIVE Phase 7.5",
        "events": count,
        "mode": app_state.get("mode", "RULES"),
    }


@app.get("/login", response_class=HTMLResponse)
async def login_trap(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def trap_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    ip = request.client.host
    db = SessionLocal()

    cmd = f"login:{username}:{password}"
    sudo_flag = 1 if "sudo" in cmd.lower() else 0
    wget_curl = 1 if any(p in cmd.lower() for p in ["wget", "curl", "tftp"]) else 0

    features = compute_ml_features_v2(db, ip, cmd, sudo_flag, wget_curl)
    model = app_state.get("model")
    attack_class = "normal"
    if model:
        attack_class, _ = predict_attack_v2(model, features)

    severity = compute_severity_v2(cmd, attack_class)

    event = Event(
        source_ip=ip,
        username=username,
        password=password,
        event_type="web",
        command=cmd,
        attack_class=attack_class,
        severity=severity,
        timestamp=get_ist_now(),
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
            "cmd": cmd[:50],
            "severity": severity,
            "attack_class": attack_class,
        },
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
    except Exception:
        username, password = "malformed", "malformed"

    db = SessionLocal()
    cmd = f"json_login:{username}"

    sudo_flag = 1 if "sudo" in cmd.lower() else 0
    wget_curl = 1 if any(p in cmd.lower() for p in ["wget", "curl", "tftp"]) else 0

    features = compute_ml_features_v2(db, ip, cmd, sudo_flag, wget_curl)
    model = app_state.get("model")
    attack_class = "normal"
    if model:
        attack_class, _ = predict_attack_v2(model, features)

    severity = compute_severity_v2(cmd, attack_class)

    event = Event(
        source_ip=ip,
        username=username,
        password=password,
        event_type="web",
        command=cmd,
        attack_class=attack_class,
        severity=severity,
        timestamp=get_ist_now(),
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
            "cmd": cmd[:50],
            "severity": severity,
            "attack_class": attack_class,
        },
    }
    asyncio.create_task(broadcast_event(event_data))

    return {"status": "logged", "attack_class": attack_class}


@app.post("/ingest_ssh")
async def ingest_ssh(
    ip: str = Form(...),
    username: str = Form("unknown"),
    command: str = Form(...),
    session_id: str = Form("ssh"),
):
    db = SessionLocal()

    sudo_flag = 1 if "sudo" in command.lower() else 0
    wget_curl = 1 if any(p in command.lower() for p in ["wget", "curl", "tftp"]) else 0

    features = compute_ml_features_v2(db, ip, command, sudo_flag, wget_curl)
    model = app_state.get("model")
    attack_class = "normal"
    if model:
        attack_class, _ = predict_attack_v2(model, features)

    severity = compute_severity_v2(command, attack_class)

    event = Event(
        source_ip=ip,
        username=username,
        event_type="ssh",
        command=command,
        attack_class=attack_class,
        severity=severity,
        timestamp=get_ist_now(),
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
            "attack_class": attack_class,
        },
    }
    asyncio.create_task(broadcast_event(event_data))

    return {
        "status": "logged",
        "severity": severity,
        "attack_class": attack_class,
    }


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
            "attack_class": getattr(e, "attack_class", "N/A"),
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
    writer.writerow(
        ["IP", "Type", "Time(IST)", "Command", "Severity", "Attack Class"]
    )
    for e in events:
        writer.writerow(
            [
                e.source_ip,
                e.event_type,
                format_time(e.timestamp),
                getattr(e, "command", "N/A"),
                getattr(e, "severity", "LOW"),
                getattr(e, "attack_class", "N/A"),
            ]
        )
    return HTMLResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=attacks.csv"},
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
            "attack_class": getattr(e, "attack_class", "N/A"),
        }
        for e in events
    ]

    model_info = app_state.get("model_info")

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "events": events_data,
            "total_events": total,
            "web_count": web,
            "ssh_count": ssh,
            "mode": app_state.get("mode", "RULES"),
            "model_info": model_info,
        },
    )


# --- Phase 7 RF endpoint (96%) ---
class PredictRequest(BaseModel):
    cmd_len: float
    sudo_flag: int
    wget_curl: int
    ip_freq: float


@app.post("/predict", response_model=dict)
async def predict_endpoint(req: PredictRequest):
    model = app_state.get("model")
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    # Match Phase 7 training features
    data_df = pd.DataFrame(
        [[req.cmd_len, req.sudo_flag, req.wget_curl, req.ip_freq]],
        columns=["cmd_len", "sudo_flag", "wget_curl", "ip_freq"],
    )

    pred_class = model.predict(data_df)[0]
    proba = model.predict_proba(data_df)[0]
    confidence = float(np.max(proba))

    attack_types = {0: "normal", 1: "attack"}
    attack_type = attack_types.get(int(pred_class), "unknown")

    return {
        "attack_type": attack_type,
        "confidence": confidence,
        "class_id": int(pred_class),
        "probabilities": {str(int(k)): float(v) for k, v in enumerate(proba)},
    }


# --- Re‑classify ALL events with Phase 7 model ---
@app.post("/backfill_ml")
async def backfill_ml_events(background_tasks: BackgroundTasks):
    model = app_state.get("model")
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    db_session = SessionLocal()
    total_count = db_session.execute(
        text("SELECT COUNT(*) FROM events")
    ).scalar()
    db_session.close()

    print(f"Re‑classifying ALL {total_count} events...")

    def reclassify_all():
        db = SessionLocal()
        try:
            events_result = db.execute(
                text(
                    "SELECT id, source_ip, command, event_type FROM events ORDER BY id"
                )
            )
            events = events_result.fetchall()

            updated = 0
            for row in events:
                # Bind fields explicitly to avoid mapping fragility
                event_dict = dict(row._mapping)
                ip = event_dict.get("source_ip") or "unknown"
                cmd = event_dict.get("command") or ""
                event_type = event_dict.get("event_type", "ssh")

                sudo_flag = 1 if "sudo" in cmd.lower() else 0
                wget_curl = 1 if any(p in cmd.lower() for p in ["wget", "curl", "tftp"]) else 0
                ip_freq = get_ip_freq(db, ip)
                features = compute_ml_features_v2(db, ip, cmd, sudo_flag, wget_curl)

                attack_class, confidence = predict_attack_v2(model, features)
                severity = compute_severity_v2(cmd, attack_class)

                db.execute(
                    text(
                        """
                        UPDATE events
                        SET attack_class = :attack_class,
                            severity = :severity,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = :id
                        """
                    ),
                    {
                        "attack_class": attack_class,
                        "severity": severity,
                        "id": event_dict["id"],
                    },
                )
                updated += 1

                if updated % 10 == 0:
                    db.commit()
                    print(f"Progress: {updated}/{len(events)}")

            db.commit()
            print(f"Re‑classified all: {updated}/{total_count} events")

        except Exception as e:
            print(f"Error during backfill: {e}")
            db.rollback()
        finally:
            db.close()

    background_tasks.add_task(reclassify_all)
    return {
        "status": "reclassify_queued",
        "total_events": total_count,
        "message": f"Re‑classifying {total_edges} events in background",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
