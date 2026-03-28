from __future__ import annotations

from fastapi import FastAPI, Request, Depends, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    Float,
    Boolean,
    inspect,
    text,
    func,
)
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
import json
import pickle
import threading
import time
import webbrowser

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

app_state: Dict[str, Any] = {}
session_commands: Dict[str, List[str]] = defaultdict(list)
bad_actors: Dict[str, Dict[str, Any]] = {}

decoys_dir = Path("app/decoys")
decoys_dir.mkdir(parents=True, exist_ok=True)

lstm_model = None
lstm_tokenizer = None
lstm_label_encoder = None

DATABASE_URL = "sqlite:///data/events.db"
Path("data").mkdir(parents=True, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


# =========================
# Database Model
# =========================
class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    session_id = Column(String, default="unknown")
    source_ip = Column(String, nullable=False)
    username = Column(String, default="unknown")
    event_type = Column(String, default="ssh")

    command = Column(String, default="")
    attack_class = Column(String, default="normal")

    severity = Column(String, default="LOW")
    threat_score = Column(Float, default=0.0)

    lstm_session = Column(String, default="Unknown")
    lstm_score = Column(Float, default=0.0)
    command_score = Column(Float, default=0.0)

    ciciot_attack = Column(String, default=None)
    ciciot_confidence = Column(Float, default=0.0)
    ciciot_score = Column(Float, default=0.0)

    decision_source = Column(String, default="rules")
    fusion_method = Column(String, default="hybrid_lstm_ciciot_command")

    base_severity = Column(String, default="LOW")
    floor_severity = Column(String, default="LOW")
    policy_escalated = Column(Boolean, default=False)

    action_taken = Column(String, default="logged")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_event_columns():
    inspector = inspect(engine)
    if not inspector.has_table("events"):
        return

    columns = {col["name"] for col in inspector.get_columns("events")}

    alter_statements = {
        "session_id": "ALTER TABLE events ADD COLUMN session_id VARCHAR DEFAULT 'unknown'",
        "lstm_session": "ALTER TABLE events ADD COLUMN lstm_session VARCHAR DEFAULT 'Unknown'",
        "lstm_score": "ALTER TABLE events ADD COLUMN lstm_score FLOAT DEFAULT 0.0",
        "command_score": "ALTER TABLE events ADD COLUMN command_score FLOAT DEFAULT 0.0",
        "ciciot_score": "ALTER TABLE events ADD COLUMN ciciot_score FLOAT DEFAULT 0.0",
        "fusion_method": "ALTER TABLE events ADD COLUMN fusion_method VARCHAR DEFAULT 'hybrid_lstm_ciciot_command'",
        "base_severity": "ALTER TABLE events ADD COLUMN base_severity VARCHAR DEFAULT 'LOW'",
        "floor_severity": "ALTER TABLE events ADD COLUMN floor_severity VARCHAR DEFAULT 'LOW'",
        "policy_escalated": "ALTER TABLE events ADD COLUMN policy_escalated BOOLEAN DEFAULT 0",
        "action_taken": "ALTER TABLE events ADD COLUMN action_taken VARCHAR DEFAULT 'logged'",
    }

    with engine.begin() as conn:
        for col_name, stmt in alter_statements.items():
            if col_name not in columns:
                conn.execute(text(stmt))


# =========================
# Pydantic Models
# =========================
class CICIoTRequest(BaseModel):
    features: Dict[str, Any]


class LSTMPredictRequest(BaseModel):
    session_id: str = "default"
    command: str


class HybridPredictRequest(BaseModel):
    session_id: str = "default"
    command: str
    event_type: str = "ssh"
    ciciot_features: Optional[Dict[str, Any]] = None


class SSHIngestRequest(BaseModel):
    ip: str = Field(..., description="Source IP address")
    username: str = "unknown"
    command: str
    session_id: str = "ssh"
    event_type: str = "ssh"
    ciciot_features: Optional[Dict[str, Any]] = None


class WebIngestRequest(BaseModel):
    ip: str = Field(..., description="Source IP address")
    session_id: str = "web"
    event_type: str = "web"
    activity: str = Field(..., description="HTTP or network activity summary")
    username: str = "web-anon"
    ciciot_features: Optional[Dict[str, Any]] = None


# =========================
# Helpers
# =========================
def now_utc() -> datetime:
    return datetime.utcnow()


def format_time(ts: Optional[datetime]) -> str:
    if not ts:
        return "-"
    if ts.tzinfo is None:
        ts = pytz.utc.localize(ts)
    return ts.astimezone(IST).strftime("%H:%M:%S")


def load_json_if_exists(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def severity_rank(severity: str) -> int:
    mapping = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    return mapping.get((severity or "LOW").upper(), 1)


def normalize_severity(severity: str) -> str:
    sev = (severity or "LOW").upper()
    return sev if sev in {"LOW", "MEDIUM", "HIGH"} else "LOW"


def normalize_event_type(event_type: Optional[str], default: str = "ssh") -> str:
    value = (event_type or default).strip().lower()
    if value in {"ssh", "web"}:
        return value
    return default


def severity_from_score(score: float) -> str:
    if score >= 0.75:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    return "LOW"


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def build_model_session_id(event_type: str, session_id: str) -> str:
    normalized_type = normalize_event_type(event_type, default="ssh")
    raw_session = (session_id or normalized_type).strip()
    return f"{normalized_type}:{raw_session}"


def normalize_attack_label(raw_label: Optional[str]) -> Optional[str]:
    if not raw_label:
        return None

    label = str(raw_label).strip().lower()
    if not label:
        return None

    benign_terms = {"benign", "normal", "harmless", "none", "unknown"}
    if label in benign_terms:
        return "normal"

    ddos_terms = [
        "ddos", "dos", "syn flood", "synflood", "udp flood",
        "icmp flood", "ack flood", "http flood", "flood"
    ]
    if any(term in label for term in ddos_terms):
        return "ddos"

    recon_terms = [
        "scan", "recon", "reconnaissance", "portscan",
        "port scan", "host discovery", "service discovery", "enumeration"
    ]
    if any(term in label for term in recon_terms):
        return "reconnaissance"

    brute_terms = ["bruteforce", "brute force", "dictionary", "credential"]
    if any(term in label for term in brute_terms):
        return "credential_attack"

    exploit_terms = ["exploit", "malware", "backdoor", "rce", "injection", "shell", "payload"]
    if any(term in label for term in exploit_terms):
        return "exploitation"

    bot_terms = ["bot", "botnet", "c2", "command and control"]
    if any(term in label for term in bot_terms):
        return "botnet_activity"

    if "web" in label:
        return "web_attack"

    return label.replace(" ", "_")


def classify_ssh_attack(command: str, lstm_session: Optional[str] = None) -> str:
    cmd = (command or "").lower()
    lstm_label = (lstm_session or "").lower()

    if not cmd.strip():
        return "normal"

    recon_tokens = [
        "nmap", "masscan", "nikto", "enum4linux", "sqlmap",
        "scan", "recon", "netstat", "ss ", "ifconfig", "ip a",
        "whois", "dig ", "nslookup"
    ]
    credential_tokens = [
        "hydra", "medusa", "patator", "john", "hashcat",
        "cat /etc/shadow", "/etc/passwd"
    ]
    privilege_tokens = [
        "sudo", "su ", "passwd", "useradd", "usermod", "chsh",
        "systemctl", "service ", "crontab"
    ]
    exploit_tokens = [
        "wget ", "curl ", "chmod +x", "./", "| bash", "| sh",
        "bash -i", "/bin/bash -i", "python -c", "perl -e",
        "nc -e", "nohup", "reverse shell", "payload", "command injection"
    ]
    destructive_tokens = [
        "rm -rf", "mkfs", "dd if=", "truncate", "shred"
    ]

    if any(token in cmd for token in destructive_tokens):
        return "destructive_activity"
    if any(token in cmd for token in exploit_tokens):
        return "exploitation"
    if any(token in cmd for token in credential_tokens):
        return "credential_attack"
    if any(token in cmd for token in privilege_tokens):
        return "privilege_abuse"
    if any(token in cmd for token in recon_tokens):
        return "reconnaissance"

    if any(term in lstm_label for term in ["malware", "exploit", "shell", "payload", "backdoor"]):
        return "exploitation"
    if any(term in lstm_label for term in ["bruteforce", "credential"]):
        return "credential_attack"
    if any(term in lstm_label for term in ["scan", "recon", "enumeration"]):
        return "reconnaissance"

    return "normal"


def classify_web_attack(activity: str) -> str:
    text = (activity or "").lower()

    if not text.strip():
        return "normal"

    ddos_tokens = [
        "http flood", "udp flood", "syn flood", "ack flood",
        "icmp flood", "slowloris", "rate limit exceeded",
        "too many requests", "traffic spike", "flood"
    ]
    credential_tokens = [
        "post /login", "post /signin", "post /auth", "post /session",
        "wp-login", "xmlrpc.php", "bruteforce", "brute force",
        "credential stuffing", "invalid password", "failed login"
    ]
    recon_tokens = [
        "get /admin", "get /administrator", "get /.env", "get /.git",
        "get /phpmyadmin", "get /wp-admin", "get /manager/html",
        "head /", "options /", "trace /", "nikto", "scan attempt",
        "dirb", "gobuster", "ffuf", "enumeration", "probe"
    ]
    injection_tokens = [
        "union select", "' or 1=1", "\" or 1=1", "sql injection",
        "<script", "xss", "../", "..\\", "/etc/passwd", "lfi", "rfi",
        "cmd=", "exec=", "powershell", "shellshock", "jndi:", "${jndi"
    ]
    upload_exec_tokens = [
        "file upload", "webshell", ".php", ".jsp", ".aspx",
        "cmd.php", "shell.php", "malicious payload"
    ]

    if any(token in text for token in ddos_tokens):
        return "ddos"
    if any(token in text for token in upload_exec_tokens):
        return "exploitation"
    if any(token in text for token in injection_tokens):
        return "web_attack"
    if any(token in text for token in credential_tokens):
        return "credential_attack"
    if any(token in text for token in recon_tokens):
        return "reconnaissance"

    if text.startswith("get /"):
        return "reconnaissance"
    if text.startswith("post /login") or text.startswith("post /signin"):
        return "credential_attack"

    return "normal"


def resolve_attack_class(
    *,
    event_type: str,
    raw_text: str,
    lstm_session: Optional[str],
    ciciot_attack: Optional[str],
    ciciot_score: float,
    command_score: float,
    threat_score: float,
) -> str:
    normalized_type = normalize_event_type(event_type)
    normalized_ciciot = normalize_attack_label(ciciot_attack)

    if normalized_type == "ssh":
        ssh_label = classify_ssh_attack(raw_text, lstm_session=lstm_session)
        if ssh_label != "normal":
            return ssh_label

        if normalized_ciciot in {"credential_attack", "exploitation", "reconnaissance", "botnet_activity"}:
            return normalized_ciciot

        if normalized_ciciot == "ddos":
            if ciciot_score >= 0.92 and threat_score >= 0.80:
                return "ddos"

        return "normal"

    web_label = classify_web_attack(raw_text)
    if web_label != "normal":
        return web_label

    if normalized_ciciot == "ddos":
        ddos_hints = [
            "flood", "traffic spike", "packet storm", "syn", "udp", "icmp",
            "too many requests", "rate limit", "volumetric"
        ]
        raw_lower = (raw_text or "").lower()
        if any(h in raw_lower for h in ddos_hints) or ciciot_score >= 0.90:
            return "ddos"
        return "web_attack" if threat_score >= 0.50 else "normal"

    if normalized_ciciot in {"reconnaissance", "credential_attack", "web_attack", "exploitation", "botnet_activity"}:
        return normalized_ciciot

    if command_score >= 0.65 or threat_score >= 0.60:
        return "web_attack"

    return "normal"


def score_command_risk(command: str) -> float:
    cmd = (command or "").strip().lower()
    if not cmd:
        return 0.0

    exact_benign = {
        "ls", "pwd", "whoami", "id", "date", "uname", "hostname",
        "echo", "clear", "history"
    }
    if cmd in exact_benign:
        return 0.05

    if any(cmd == item or cmd.startswith(item + " ") for item in ["cat", "head", "tail", "cd", "find", "ps", "top", "df", "du"]):
        return 0.15

    score = 0.20

    medium_tokens = [
        "netstat", "ss", "ifconfig", "ip a", "ping", "scp", "ftp", "telnet",
        "ssh ", "curl ", "wget ", "nc ", "netcat", "nmap", "masscan",
        "hydra", "sqlmap", "nikto", "enum4linux", "scan", "recon",
        "post /login", "get /admin", "wp-login", "bruteforce"
    ]
    suspicious_tokens = [
        "http://", "https://", "/tmp/", "base64", "bash -c", "sh -c",
        "sudo", "nohup", "systemctl", "crontab", "useradd",
        "../", "union select", " or 1=1", "<script", "payload", "suspicious"
    ]
    critical_tokens = [
        "chmod +x", "./", "bash -i", "/bin/bash -i", "python -c", "perl -e",
        "rm -rf", "mkfs", "dd if=", "cat /etc/shadow", "nc -e",
        "reverse shell", "command injection"
    ]

    for token in medium_tokens:
        if token in cmd:
            score += 0.18

    for token in suspicious_tokens:
        if token in cmd:
            score += 0.12

    for token in critical_tokens:
        if token in cmd:
            score += 0.28

    has_download = any(token in cmd for token in ["wget ", "curl ", "http://", "https://"])
    has_permission_change = "chmod +x" in cmd
    has_direct_exec = any(token in cmd for token in ["./", "bash ", "sh ", "python -c", "perl -e", "nohup"])
    has_pipe_exec = ("| bash" in cmd) or ("| sh" in cmd)
    has_reverse_shell = any(token in cmd for token in ["nc -e", "/bin/bash -i", "bash -i", "python -c", "perl -e", "reverse shell"])
    has_destructive = any(token in cmd for token in ["rm -rf", "mkfs", "dd if="])
    has_credential_access = any(token in cmd for token in ["cat /etc/shadow", "/etc/passwd"])

    if has_download and has_permission_change and has_direct_exec:
        return 0.96
    if has_pipe_exec:
        return 0.97
    if has_reverse_shell:
        return 0.98
    if has_destructive:
        return 0.99
    if has_credential_access:
        return 0.95

    if has_download and has_direct_exec:
        score += 0.22
    if "&&" in cmd:
        score += 0.06
    if ";" in cmd:
        score += 0.04

    return round(clamp01(score), 4)


def floor_severity_from_command(command: str, event_type: str = "ssh") -> str:
    cmd = (command or "").strip().lower()
    normalized_type = normalize_event_type(event_type)

    if not cmd:
        return "LOW"

    if normalized_type == "web":
        forced_high_patterns = [
            "sql injection" in cmd,
            "command injection" in cmd,
            "shellshock" in cmd,
            "${jndi" in cmd,
            "jndi:" in cmd,
            "<script" in cmd and "admin" in cmd,
            "webshell" in cmd,
            "shell.php" in cmd,
            "cmd.php" in cmd,
            "../" in cmd and "/etc/passwd" in cmd,
        ]
        if any(forced_high_patterns):
            return "HIGH"

        forced_medium_patterns = [
            "get /admin" in cmd,
            "get /phpmyadmin" in cmd,
            "get /wp-admin" in cmd,
            "post /login" in cmd,
            "wp-login" in cmd,
            "scan attempt" in cmd,
            "nikto" in cmd,
            "gobuster" in cmd,
            "ffuf" in cmd,
            "union select" in cmd,
            "<script" in cmd,
            "../" in cmd,
        ]
        if any(forced_medium_patterns):
            return "MEDIUM"

        score = score_command_risk(command)
        if score >= 0.85:
            return "HIGH"
        if score >= 0.55:
            return "MEDIUM"
        return "LOW"

    forced_high_patterns = [
        ("wget " in cmd or "curl " in cmd or "http://" in cmd or "https://" in cmd)
        and "chmod +x" in cmd
        and "./" in cmd,

        "| bash" in cmd,
        "| sh" in cmd,

        "nc -e" in cmd,
        "/bin/bash -i" in cmd,
        "bash -i" in cmd,
        "python -c" in cmd,
        "perl -e" in cmd,

        "rm -rf" in cmd,
        "mkfs" in cmd,
        "dd if=" in cmd,
        "cat /etc/shadow" in cmd,
        "reverse shell" in cmd,
        "command injection" in cmd,
    ]

    if any(forced_high_patterns):
        return "HIGH"

    forced_medium_patterns = [
        "nmap" in cmd,
        "masscan" in cmd,
        "hydra" in cmd,
        "sqlmap" in cmd,
        "nikto" in cmd,
        "enum4linux" in cmd,
        "wget " in cmd,
        "curl " in cmd,
        "sudo" in cmd,
        "crontab" in cmd,
        "systemctl" in cmd,
        "scan" in cmd,
        "recon" in cmd,
        "wp-login" in cmd,
        "../" in cmd,
        "union select" in cmd,
        "<script" in cmd,
    ]

    if any(forced_medium_patterns):
        return "MEDIUM"

    score = score_command_risk(command)
    if score >= 0.85:
        return "HIGH"
    if score >= 0.55:
        return "MEDIUM"
    return "LOW"


def create_decoy_files():
    decoys = {
        "aws_keys.txt": "AWS_ACCESS_KEY_ID=AKIAxxxxxxxxxxxx\nAWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxx",
        "db_backup.sql": "-- fake backup\nCREATE TABLE users(id INT, username TEXT, password TEXT);",
        "payroll_2026.xlsx": "This is a decoy spreadsheet placeholder.",
        "prod_server_passwords.txt": "root: hunter2\nadmin: password123",
    }
    for name, content in decoys.items():
        fp = decoys_dir / name
        if not fp.exists():
            fp.write_text(content, encoding="utf-8")


# =========================
# Rate Limiting / Actor Escalation
# =========================
class RateLimiter:
    def __init__(self, max_requests: int = 12, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)

    def check(self, ip: str) -> Dict[str, Any]:
        now = time.time()
        q = self.requests[ip]

        while q and (now - q[0] > self.window_seconds):
            q.popleft()

        q.append(now)

        blocked = len(q) > self.max_requests
        return {
            "count": len(q),
            "window_seconds": self.window_seconds,
            "blocked": blocked,
        }


rate_limiter = RateLimiter(max_requests=12, window_seconds=60)


def update_bad_actor_state(ip: str, event_payload: Dict[str, Any]) -> Dict[str, Any]:
    state = bad_actors.setdefault(
        ip,
        {
            "high_alerts": 0,
            "medium_alerts": 0,
            "malicious_events": 0,
            "latest_severity": "LOW",
            "last_attack": "normal",
            "max_threat_score": 0.0,
            "enforcement": "monitor",
            "last_seen": None,
        },
    )

    severity = normalize_severity(event_payload.get("severity"))
    threat_score = float(event_payload.get("threat_score", 0.0))
    attack_class = event_payload.get("attack_class", "normal")

    if severity == "HIGH":
        state["high_alerts"] += 1

    if severity in {"MEDIUM", "HIGH"}:
        state["medium_alerts"] += 1

    if attack_class != "normal" or severity in {"MEDIUM", "HIGH"} or threat_score >= 0.40:
        state["malicious_events"] += 1

    state["latest_severity"] = severity
    state["last_attack"] = attack_class
    state["max_threat_score"] = max(float(state.get("max_threat_score", 0.0)), threat_score)
    state["last_seen"] = now_utc().isoformat()

    high_alerts = int(state["high_alerts"])
    medium_alerts = int(state["medium_alerts"])
    malicious_events = int(state["malicious_events"])
    max_threat = float(state["max_threat_score"])

    if (
        high_alerts >= 2
        or medium_alerts >= 5
        or malicious_events >= 5
        or threat_score >= 0.92
        or max_threat >= 0.95
    ):
        state["enforcement"] = "escalated"
    elif (
        high_alerts >= 1
        or medium_alerts >= 3
        or malicious_events >= 3
        or threat_score >= 0.75
        or max_threat >= 0.80
    ):
        state["enforcement"] = "watch"
    else:
        state["enforcement"] = "monitor"

    return state


def rebuild_bad_actor_state_from_db(db: Session) -> None:
    global bad_actors
    bad_actors.clear()

    events = (
        db.query(Event)
        .order_by(Event.timestamp.asc(), Event.id.asc())
        .all()
    )

    for event in events:
        source_ip = (event.source_ip or "").strip()
        if not source_ip:
            continue

        update_bad_actor_state(
            source_ip,
            {
                "severity": event.severity or "LOW",
                "threat_score": float(event.threat_score or 0.0),
                "attack_class": event.attack_class or "normal",
            },
        )


# =========================
# App Lifespan / Model Loading
# =========================
@asynccontextmanager
async def lifespan(app_: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_event_columns()
    create_decoy_files()

    with SessionLocal() as db:
        rebuild_bad_actor_state_from_db(db)
        print(f"Rebuilt bad actor state from DB: {len(bad_actors)} tracked actors")

    app_state["rf_model"] = None
    app_state["rf_features"] = []
    app_state["rf_info"] = {
        "status": "disabled",
        "reason": "Legacy RF removed from live runtime due to invalid or mismatched artifact",
        "type": "legacy_honeypot_rf",
    }

    app_state["ciciot_model"] = None
    app_state["ciciot_features"] = []
    app_state["ciciot_info"] = {}

    ciciot_model_path = Path("app/ciciot_rf_model.pkl")
    ciciot_features_path = Path("app/ciciot_feature_columns.pkl")

    if ciciot_model_path.exists() and ciciot_features_path.exists():
        try:
            ciciot_model = joblib.load(ciciot_model_path)
            ciciot_features = joblib.load(ciciot_features_path)

            app_state["ciciot_model"] = ciciot_model
            app_state["ciciot_features"] = list(ciciot_features)
            app_state["ciciot_info"] = {
                "version": "CICIoT2023 RF v1",
                "features_count": len(app_state["ciciot_features"]),
                "classes": list(getattr(ciciot_model, "classes_", [])),
                "status": "loaded",
                "type": "ciciot2023_multiclass_rf",
            }
            print("Loaded CICIoT2023 RF model")
        except Exception as e:
            app_state["ciciot_info"] = {
                "status": f"failed: {e}",
                "type": "ciciot2023_multiclass_rf",
            }
            print(f"CICIoT load failed: {e}")
    else:
        app_state["ciciot_info"] = {
            "status": "missing artifacts",
            "type": "ciciot2023_multiclass_rf",
        }

    global lstm_model, lstm_tokenizer, lstm_label_encoder
    lstm_model = None
    lstm_tokenizer = None
    lstm_label_encoder = None
    app_state["lstm_info"] = {}

    lstm_model_path = Path("app/lstm_ssh_v8.keras")
    lstm_tokenizer_path = Path("app/lstm_tokenizer.pkl")
    lstm_encoder_path = Path("app/lstm_label_encoder.pkl")
    lstm_metadata_path = Path("app/lstm_metadata.json")

    if all(p.exists() for p in [lstm_model_path, lstm_tokenizer_path, lstm_encoder_path]):
        try:
            lstm_model = keras.models.load_model(str(lstm_model_path))
            with open(lstm_tokenizer_path, "rb") as f:
                lstm_tokenizer = pickle.load(f)
            with open(lstm_encoder_path, "rb") as f:
                lstm_label_encoder = pickle.load(f)

            lstm_meta = load_json_if_exists(lstm_metadata_path)
            app_state["lstm_info"] = {
                "version": lstm_meta.get("version", "LSTM v8.1"),
                "accuracy": float(lstm_meta.get("accuracy", 0.979)),
                "trained_samples": int(lstm_meta.get("trained_samples", 233000)),
                "classes": int(lstm_meta.get("classes", 9)),
                "max_sequence_length": int(lstm_meta.get("max_sequence_length", 100)),
                "status": "loaded",
                "type": "ssh_sequence_lstm",
            }
            print(f"Loaded LSTM: {app_state['lstm_info']['version']}")
        except Exception as e:
            lstm_model = None
            lstm_tokenizer = None
            lstm_label_encoder = None
            app_state["lstm_info"] = {
                "status": f"failed: {e}",
                "type": "ssh_sequence_lstm",
            }
            print(f"LSTM load failed: {e}")
    else:
        app_state["lstm_info"] = {
            "status": "missing artifacts",
            "type": "ssh_sequence_lstm",
        }

    app_state["hybrid_info"] = "LSTM + CICIoT + Command-Risk Hybrid Decision Engine Active"
    print("Honeypot backend ready")

    yield


# =========================
# App Initialization
# =========================
app = FastAPI(title="Honeypot SOC", lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/decoys", StaticFiles(directory="app/decoys"), name="decoys")


# =========================
# WebSocket Manager
# =========================
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, payload: Dict[str, Any]):
        dead = []
        for ws in self.active_connections[:]:
            try:
                await ws.send_text(json.dumps(payload, default=str))
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# =========================
# ML Prediction Helpers
# =========================
def predict_ciciot_from_dict(feature_dict: Dict[str, Any]) -> Dict[str, Any]:
    model = app_state.get("ciciot_model")
    feature_columns = app_state.get("ciciot_features", [])

    if model is None or not feature_columns:
        raise HTTPException(status_code=503, detail="CICIoT model not loaded")

    row = {}
    for col in feature_columns:
        raw = feature_dict.get(col, 0.0)
        try:
            row[col] = float(raw)
        except Exception:
            row[col] = 0.0

    data_df = pd.DataFrame([row], columns=feature_columns)
    pred = model.predict(data_df)[0]

    confidence = 0.0
    if hasattr(model, "predict_proba"):
        try:
            probs = model.predict_proba(data_df)[0]
            confidence = float(np.max(probs))
        except Exception:
            confidence = 0.0

    attack = str(pred)
    attack_lower = attack.lower()

    if attack_lower in {"benign", "normal"}:
        score = 0.0
    elif any(token in attack_lower for token in ["dos", "ddos"]):
        score = max(confidence, 0.75)
    elif any(token in attack_lower for token in ["scan", "recon", "bruteforce"]):
        score = max(confidence * 0.9, 0.60)
    else:
        score = max(confidence * 0.85, 0.45)

    return {
        "ciciot_attack": attack,
        "ciciot_confidence": round(float(confidence), 4),
        "ciciot_score": round(clamp01(score), 4),
    }


def map_lstm_label_to_score(label: str, prob: float) -> float:
    label_lower = (label or "").lower()

    benign_terms = ["benign", "normal", "harmless"]
    medium_terms = ["scan", "recon", "suspicious", "enumeration"]
    high_terms = ["malware", "payload", "exploit", "shell", "bruteforce", "backdoor", "attack"]

    if any(term in label_lower for term in benign_terms):
        return 0.05 * max(prob, 0.5)
    if any(term in label_lower for term in medium_terms):
        return 0.45 + 0.30 * prob
    if any(term in label_lower for term in high_terms):
        return 0.70 + 0.25 * prob

    return 0.25 + 0.30 * prob


def predict_lstm_from_session(session_id: str, command: str) -> Dict[str, Any]:
    session_commands[session_id].append(command)
    sequence = session_commands[session_id][-100:]

    if lstm_model is None or lstm_tokenizer is None or lstm_label_encoder is None:
        return {
            "lstm_session": "Unavailable",
            "session_length": len(sequence),
            "lstm_score": round(score_command_risk(command) * 0.5, 4),
            "lstm_confidence": 0.0,
        }

    joined = " ; ".join(sequence)
    try:
        seq = lstm_tokenizer.texts_to_sequences([joined])
        max_len = int(app_state.get("lstm_info", {}).get("max_sequence_length", 100))
        padded = keras.preprocessing.sequence.pad_sequences(seq, maxlen=max_len, padding="post")
        preds = lstm_model.predict(padded, verbose=0)[0]

        pred_idx = int(np.argmax(preds))
        pred_label = str(lstm_label_encoder.inverse_transform([pred_idx])[0])
        pred_prob = float(preds[pred_idx])

        lstm_score = clamp01(map_lstm_label_to_score(pred_label, pred_prob))
        return {
            "lstm_session": pred_label,
            "session_length": len(sequence),
            "lstm_score": round(float(lstm_score), 4),
            "lstm_confidence": round(pred_prob, 4),
        }
    except Exception:
        return {
            "lstm_session": "Fallback",
            "session_length": len(sequence),
            "lstm_score": round(score_command_risk(command) * 0.5, 4),
            "lstm_confidence": 0.0,
        }


def fuse_hybrid_decision(
    command: str,
    session_id: str,
    event_type: str = "ssh",
    ciciot_features: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    normalized_type = normalize_event_type(event_type)
    lstm_result = predict_lstm_from_session(session_id=session_id, command=command)
    command_score = round(score_command_risk(command), 4)
    floor_severity = floor_severity_from_command(command, event_type=normalized_type)

    ciciot_result = {
        "ciciot_attack": None,
        "ciciot_confidence": 0.0,
        "ciciot_score": 0.0,
    }
    if ciciot_features:
        try:
            ciciot_result = predict_ciciot_from_dict(ciciot_features)
        except HTTPException:
            pass
        except Exception:
            pass

    lstm_score = float(lstm_result["lstm_score"])
    ciciot_score = float(ciciot_result["ciciot_score"])

    if normalized_type == "web":
        if ciciot_features:
            threat_score = 0.45 * command_score + 0.20 * lstm_score + 0.35 * ciciot_score
        else:
            threat_score = 0.70 * command_score + 0.30 * lstm_score
    else:
        if ciciot_features:
            threat_score = 0.40 * command_score + 0.30 * lstm_score + 0.30 * ciciot_score
        else:
            threat_score = 0.55 * command_score + 0.45 * lstm_score

    threat_score = round(clamp01(threat_score), 4)

    base_severity = severity_from_score(threat_score)
    final_severity = max_severity(base_severity, floor_severity)
    policy_escalated = final_severity != base_severity

    attack_class = resolve_attack_class(
        event_type=normalized_type,
        raw_text=command,
        lstm_session=lstm_result.get("lstm_session"),
        ciciot_attack=ciciot_result.get("ciciot_attack"),
        ciciot_score=ciciot_score,
        command_score=command_score,
        threat_score=threat_score,
    )

    if ciciot_features and ciciot_score >= max(command_score, lstm_score):
        decision_source = "hybrid"
    elif lstm_score >= command_score:
        decision_source = "lstm"
    else:
        decision_source = "command"

    return {
        "severity": final_severity,
        "threat_score": threat_score,
        "attack_class": attack_class,
        "decision_source": decision_source,
        "fusion_method": "hybrid_lstm_ciciot_command",
        "base_severity": base_severity,
        "floor_severity": floor_severity,
        "policy_escalated": policy_escalated,
        "command_score": command_score,
        **lstm_result,
        **ciciot_result,
    }


def apply_enforcement(ip: str, severity: str, rl_result: Dict[str, Any], actor_state: Dict[str, Any]) -> str:
    severity = normalize_severity(severity)
    enforcement = actor_state.get("enforcement", "monitor")

    if rl_result["blocked"]:
        return "rate-limited"
    if enforcement == "escalated":
        return "escalated"
    if enforcement == "watch":
        return "watchlisted"
    if severity == "HIGH":
        return "alerted"
    return "logged"


def serialize_event(event: Event) -> Dict[str, Any]:
    return {
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "timestamp_formatted": format_time(event.timestamp),
        "session_id": event.session_id,
        "source_ip": event.source_ip,
        "username": event.username,
        "event_type": normalize_event_type(event.event_type),
        "command": event.command or "",
        "attack_class": event.attack_class or "normal",
        "severity": normalize_severity(event.severity),
        "threat_score": round(float(event.threat_score or 0.0), 4),
        "lstm_session": event.lstm_session or "Unknown",
        "lstm_score": round(float(event.lstm_score or 0.0), 4),
        "command_score": round(float(event.command_score or 0.0), 4),
        "ciciot_attack": event.ciciot_attack,
        "ciciot_confidence": round(float(event.ciciot_confidence or 0.0), 4),
        "ciciot_score": round(float(event.ciciot_score or 0.0), 4),
        "decision_source": event.decision_source or "rules",
        "fusion_method": event.fusion_method or "hybrid_lstm_ciciot_command",
        "base_severity": normalize_severity(event.base_severity or "LOW"),
        "floor_severity": normalize_severity(event.floor_severity or "LOW"),
        "policy_escalated": bool(event.policy_escalated),
        "action_taken": event.action_taken or "logged",
    }


async def broadcast_runtime_event(event_payload: Dict[str, Any]):
    await manager.broadcast_json(
        {
            "type": "new_event",
            "event": event_payload,
        }
    )

    if normalize_severity(event_payload.get("severity")) == "HIGH":
        await manager.broadcast_json(
            {
                "type": "alert",
                "severity": event_payload.get("severity"),
                "event": event_payload,
                **event_payload,
            }
        )


async def ingest_event_common(
    *,
    db: Session,
    ip: str,
    username: str,
    raw_text: str,
    session_id: str,
    event_type: str,
    ciciot_features: Optional[Dict[str, Any]],
):
    normalized_type = normalize_event_type(event_type, default="ssh" if event_type != "web" else "web")
    model_session_id = build_model_session_id(normalized_type, session_id)

    hybrid = fuse_hybrid_decision(
        command=raw_text,
        session_id=model_session_id,
        event_type=normalized_type,
        ciciot_features=ciciot_features,
    )

    rl_result = rate_limiter.check(ip)
    if rl_result["blocked"]:
        hybrid["severity"] = max_severity(hybrid["severity"], "HIGH")
        hybrid["policy_escalated"] = True
        hybrid["base_severity"] = hybrid.get("base_severity", hybrid["severity"])
        hybrid["floor_severity"] = max_severity(hybrid.get("floor_severity", "LOW"), "HIGH")
        hybrid["decision_source"] = "policy"

    actor_preview = update_bad_actor_state(
        ip,
        {
            "severity": hybrid["severity"],
            "threat_score": hybrid["threat_score"],
            "attack_class": hybrid["attack_class"],
        },
    )

    action_taken = apply_enforcement(
        ip=ip,
        severity=hybrid["severity"],
        rl_result=rl_result,
        actor_state=actor_preview,
    )

    event = Event(
        timestamp=now_utc(),
        session_id=session_id,
        source_ip=ip,
        username=username,
        event_type=normalized_type,
        command=raw_text,
        attack_class=hybrid["attack_class"],
        severity=normalize_severity(hybrid["severity"]),
        threat_score=float(hybrid["threat_score"]),
        lstm_session=hybrid["lstm_session"],
        lstm_score=float(hybrid["lstm_score"]),
        command_score=float(hybrid["command_score"]),
        ciciot_attack=hybrid["ciciot_attack"],
        ciciot_confidence=float(hybrid["ciciot_confidence"]),
        ciciot_score=float(hybrid["ciciot_score"]),
        decision_source=hybrid["decision_source"],
        fusion_method=hybrid["fusion_method"],
        base_severity=normalize_severity(hybrid["base_severity"]),
        floor_severity=normalize_severity(hybrid["floor_severity"]),
        policy_escalated=bool(hybrid["policy_escalated"]),
        action_taken=action_taken,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    event_payload = serialize_event(event)
    event_payload["rate_limit_blocked"] = rl_result["blocked"]
    event_payload["rate_limit_count"] = rl_result["count"]
    event_payload["bad_actor_enforcement"] = actor_preview["enforcement"]

    await broadcast_runtime_event(event_payload)

    return {
        "status": "ok",
        "event": event_payload,
        "rate_limit": rl_result,
        "bad_actor": actor_preview,
    }


# =========================
# Routes
# =========================
@app.get("/")
def root():
    return {
        "message": "Honeypot SOC is running",
        "dashboard": "/dashboard",
        "stats": "/stats",
        "model_info": "/model-info",
        "ingest_routes": ["/ingest_ssh", "/ingest_web", "/ingest_network"],
    }


@app.get("/model-info")
def model_info():
    return {
        "hybrid_info": app_state.get("hybrid_info", ""),
        "rf_info": app_state.get("rf_info", {}),
        "lstm_info": app_state.get("lstm_info", {}),
        "ciciot_info": app_state.get("ciciot_info", {}),
    }


@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    normalized_event_type = func.lower(func.trim(Event.event_type))
    normalized_severity = func.upper(func.trim(Event.severity))

    total_events = db.query(Event).count()
    ssh_count = db.query(Event).filter(normalized_event_type == "ssh").count()
    web_count = db.query(Event).filter(normalized_event_type == "web").count()
    high_count = db.query(Event).filter(normalized_severity == "HIGH").count()
    medium_count = db.query(Event).filter(normalized_severity == "MEDIUM").count()
    low_count = db.query(Event).filter(normalized_severity == "LOW").count()
    ciciot_attack_count = (
        db.query(Event)
        .filter(Event.ciciot_attack.isnot(None))
        .filter(func.lower(func.trim(Event.ciciot_attack)).notin_(["normal", "benign"]))
        .count()
    )
    escalated_count = db.query(Event).filter(Event.policy_escalated == True).count()  # noqa: E712

    return {
        "total_events": total_events,
        "ssh_count": ssh_count,
        "web_count": web_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "ciciot_attack_count": ciciot_attack_count,
        "policy_escalations": escalated_count,
        "bad_actors_count": len(bad_actors),
        "rate_limiter_ips": len(rate_limiter.requests),
        "bad_actors": bad_actors,
    }


@app.post("/predict_ciciot")
def predict_ciciot_route(payload: CICIoTRequest):
    return predict_ciciot_from_dict(payload.features)


@app.post("/predict_lstm")
def predict_lstm_route(payload: LSTMPredictRequest):
    return predict_lstm_from_session(payload.session_id, payload.command)


@app.post("/predict_hybrid")
def predict_hybrid_route(payload: HybridPredictRequest):
    return fuse_hybrid_decision(
        command=payload.command,
        session_id=payload.session_id,
        event_type=payload.event_type,
        ciciot_features=payload.ciciot_features,
    )


@app.post("/ingest_ssh")
async def ingest_ssh(payload: SSHIngestRequest, db: Session = Depends(get_db)):
    return await ingest_event_common(
        db=db,
        ip=payload.ip,
        username=payload.username,
        raw_text=payload.command,
        session_id=payload.session_id,
        event_type="ssh",
        ciciot_features=payload.ciciot_features,
    )


@app.post("/ingest_web")
async def ingest_web(payload: WebIngestRequest, db: Session = Depends(get_db)):
    return await ingest_event_common(
        db=db,
        ip=payload.ip,
        username=payload.username,
        raw_text=payload.activity,
        session_id=payload.session_id,
        event_type="web",
        ciciot_features=payload.ciciot_features,
    )


@app.post("/ingest_network")
async def ingest_network(payload: WebIngestRequest, db: Session = Depends(get_db)):
    return await ingest_event_common(
        db=db,
        ip=payload.ip,
        username=payload.username,
        raw_text=payload.activity,
        session_id=payload.session_id,
        event_type="web",
        ciciot_features=payload.ciciot_features,
    )


@app.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    normalized_event_type = func.lower(func.trim(Event.event_type))
    normalized_severity = func.upper(func.trim(Event.severity))

    events = db.query(Event).order_by(Event.id.desc()).limit(50).all()
    total = db.query(Event).count()
    ssh = db.query(Event).filter(normalized_event_type == "ssh").count()
    web = db.query(Event).filter(normalized_event_type == "web").count()
    high = db.query(Event).filter(normalized_severity == "HIGH").count()
    policy_escalations = db.query(Event).filter(Event.policy_escalated == True).count()  # noqa: E712

    ciciot_hits = (
        db.query(Event)
        .filter(Event.ciciot_attack.isnot(None))
        .filter(func.lower(func.trim(Event.ciciot_attack)).notin_(["normal", "benign"]))
        .count()
    )

    events_data = [serialize_event(e) for e in events]
    live_count = len(events_data)
    visible_high = sum(1 for e in events_data if (e.get("severity") or "").upper() == "HIGH")

    avg_threat = 0.0
    if events_data:
        avg_threat = sum(float(e.get("threat_score", 0) or 0) for e in events_data) / len(events_data)

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "events": events_data,
            "total_events": total,
            "ssh_count": ssh,
            "web_count": web,
            "high_count": high,
            "avg_threat": round(avg_threat, 3),
            "bad_actors_count": len(bad_actors),
            "policy_escalations": policy_escalations,
            "ciciot_attack_count": ciciot_hits,
            "live_count": live_count,
            "visible_high": visible_high,
            "lstm_info": app_state.get("lstm_info", {}),
            "ciciot_info": app_state.get("ciciot_info", {}),
        },
    )


# =========================
# Browser Auto-Open
# =========================
def open_browser():
    time.sleep(4)
    url = "http://localhost:8000/dashboard"
    try:
        webbrowser.open_new(url)
        print(f"Dashboard opened: {url}")
    except Exception as e:
        print(f"Could not auto-open browser: {e}")
        print(f"Open manually: {url}")


# =========================
# Main Runner
# =========================
if __name__ == "__main__":
    create_decoy_files()

    import uvicorn

    def start():
        time.sleep(2)
        browser_thread = threading.Thread(target=open_browser, daemon=True)
        browser_thread.start()

    threading.Thread(target=start, daemon=True).start()

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
