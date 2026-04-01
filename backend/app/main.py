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
from typing import Dict, List, Any, Optional, Tuple
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
# Model-first decision tuning
# =========================
LSTM_HIGH_CONFIDENCE = 0.75
LSTM_MEDIUM_CONFIDENCE = 0.40
CICIOT_HIGH_CONFIDENCE = 0.80
CICIOT_MEDIUM_CONFIDENCE = 0.60


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

    benign_terms = {"benign", "normal", "harmless", "none", "unknown", "unavailable", "fallback"}
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

    privilege_terms = ["privilege", "sudo", "su", "root escalation", "escalation", "privilege_abuse"]
    if any(term in label for term in privilege_terms):
        return "privilege_abuse"

    destructive_terms = ["destructive", "wiper", "rm -rf", "shred", "mkfs"]
    if any(term in label for term in destructive_terms):
        return "destructive_activity"

    exploit_terms = ["exploit", "malware", "backdoor", "rce", "injection", "shell", "payload", "exploitation"]
    if any(term in label for term in exploit_terms):
        return "exploitation"

    bot_terms = ["bot", "botnet", "c2", "command and control"]
    if any(term in label for term in bot_terms):
        return "botnet_activity"

    if "web" in label:
        return "web_attack"

    return label.replace(" ", "_")


def classify_ssh_attack_fallback(command: str, lstm_session: Optional[str] = None) -> str:
    cmd = (command or "").strip().lower()

    if not cmd:
        return "normal"

    # Treat very common shell commands as normal unless part of a stronger pattern
    exact_benign = {
        "ls", "pwd", "whoami", "id", "date", "clear", "history", "hostname", "uname"
    }
    benign_prefixes = [
        "echo ",
        "cd ",
        "ls ",
    ]

    if cmd in exact_benign or any(cmd.startswith(prefix) for prefix in benign_prefixes):
        return "normal"

    destructive_tokens = [
        "rm -rf", "mkfs", "dd if=", "truncate", "shred"
    ]
    exploit_tokens = [
        "wget ", "curl ", "chmod +x", "./", "| bash", "| sh",
        "bash -i", "/bin/bash -i", "python -c", "perl -e",
        "nc -e", "nohup", "reverse shell", "payload", "command injection"
    ]
    privilege_tokens = [
        "sudo", "sudo su", "sudo -i", "su ", "passwd", "useradd", "usermod",
        "chsh", "chpasswd", "visudo", "/etc/sudoers", "crontab", "systemctl",
        "service ", "backdoor"
    ]
    credential_tokens = [
        "hydra", "medusa", "patator", "john", "hashcat",
        "cat /etc/shadow", "shadow", "credentials dump"
    ]
    recon_tokens = [
        "nmap", "masscan", "nikto", "enum4linux", "sqlmap",
        "scan", "recon", "netstat", "ss ", "ifconfig", "ip a",
        "whois", "dig ", "nslookup", "hostname -i",
        "lsb_release", "cat /etc/os-release", "ps aux", "ps -ef",
        "cat /etc/passwd"
    ]

    if any(token in cmd for token in destructive_tokens):
        return "destructive_activity"
    if any(token in cmd for token in exploit_tokens):
        return "exploitation"
    if any(token in cmd for token in privilege_tokens):
        return "privilege_abuse"
    if any(token in cmd for token in credential_tokens):
        return "credential_attack"
    if any(token in cmd for token in recon_tokens):
        return "reconnaissance"

    lstm_label = (lstm_session or "").lower()
    if any(term in lstm_label for term in ["malware", "exploit", "shell", "payload", "backdoor", "exploitation"]):
        return "exploitation"
    if any(term in lstm_label for term in ["bruteforce", "credential"]):
        return "credential_attack"
    if any(term in lstm_label for term in ["scan", "recon", "enumeration", "reconnaissance"]):
        return "reconnaissance"
    if any(term in lstm_label for term in ["privilege", "sudo", "escalation", "privilege_abuse"]):
        return "privilege_abuse"

    return "normal"


def classify_web_attack_fallback(activity: str) -> str:
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
        "union select",
        "' or 1=1",
        "\" or 1=1",
        " or 1=1",
        "sql injection",
        "<script",
        "xss",
        "../",
        "..\\",
        "/etc/passwd",
        "lfi",
        "rfi",
        "cmd=",
        "exec=",
        "powershell",
        "shellshock",
        "jndi:",
        "${jndi",
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
        if " or 1=1" in text or "union select" in text:
            return "web_attack"
        return "credential_attack"

    return "normal"


def score_command_risk(command: str, event_type: str = "ssh") -> float:
    cmd = (command or "").strip().lower()
    normalized_type = normalize_event_type(event_type)

    if not cmd:
        return 0.0

    # =========================
    # WEB scoring
    # =========================
    if normalized_type == "web":
        score = 0.08

        if cmd.startswith("get /"):
            score = max(score, 0.18)

        if cmd.startswith("post /login") or cmd.startswith("post /signin") or cmd.startswith("post /auth"):
            score = max(score, 0.28)

        recon_tokens = [
            "get /admin", "get /administrator", "get /.env", "get /.git",
            "get /phpmyadmin", "get /wp-admin", "get /manager/html",
            "head /", "options /", "trace /", "nikto", "scan attempt",
            "dirb", "gobuster", "ffuf", "enumeration", "probe"
        ]
        injection_tokens = [
            "union select",
            "' or 1=1",
            "\" or 1=1",
            " or 1=1",
            "sql injection",
            "<script",
            "xss",
            "../",
            "..\\",
            "/etc/passwd",
            "lfi",
            "rfi",
            "cmd=",
            "exec=",
            "powershell",
            "shellshock",
            "jndi:",
            "${jndi",
        ]
        exploit_tokens = [
            "webshell", "shell.php", "cmd.php", ".jsp", ".aspx",
            "malicious payload", "file upload"
        ]
        flood_tokens = [
            "http flood", "udp flood", "syn flood", "ack flood",
            "icmp flood", "slowloris", "too many requests", "traffic spike", "flood"
        ]

        if any(token in cmd for token in recon_tokens):
            score = max(score, 0.42)

        if any(token in cmd for token in injection_tokens):
            score = max(score, 0.68)

        if any(token in cmd for token in exploit_tokens):
            score = max(score, 0.82)

        if any(token in cmd for token in flood_tokens):
            score = max(score, 0.78)

        return round(clamp01(score), 4)

    # =========================
    # SSH scoring
    # =========================
    exact_benign = {
        "ls", "pwd", "whoami", "id", "date", "clear", "history", "hostname", "uname"
    }
    benign_prefixes = [
        "echo ",
        "cd ",
        "ls ",
    ]
    if cmd in exact_benign or any(cmd.startswith(prefix) for prefix in benign_prefixes):
        return 0.03

    # Mild information-gathering that should stay LOW in demo
    low_recon_tokens = [
        "uname -a", "netstat", "ss ", "ifconfig", "ip a",
        "ps aux", "ps -ef", "env", "printenv", "cat /etc/os-release"
    ]
    if any(token in cmd for token in low_recon_tokens):
        return 0.22

    if "cat /etc/passwd" in cmd:
        return 0.38

    # Privilege escalation should be clearly stronger
    if "sudo su" in cmd or "sudo -i" in cmd or cmd == "su" or cmd.startswith("su "):
        return 0.72

    if cmd.startswith("useradd ") or cmd.startswith("usermod ") or " backdoor" in cmd:
        return 0.88

    if cmd.startswith("passwd ") or "chpasswd" in cmd:
        return 0.78

    if "/etc/sudoers" in cmd or "visudo" in cmd:
        return 0.90

    if "cat /etc/shadow" in cmd:
        return 0.95

    score = 0.20

    medium_tokens = [
        "scp", "ftp", "telnet",
        "ssh ", "curl ", "wget ", "nc ", "netcat", "nmap", "masscan",
        "hydra", "sqlmap", "nikto", "enum4linux", "scan", "recon"
    ]
    suspicious_tokens = [
        "http://", "https://", "/tmp/", "base64", "bash -c", "sh -c",
        "sudo", "nohup", "systemctl", "crontab", "useradd",
        "../", "payload", "suspicious", "passwd ", "backdoor"
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
    has_credential_access = "cat /etc/shadow" in cmd

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

    suspicious_download_names = [
        "malware.sh", "bot.sh", "payload.sh", "miner.sh", "dropper.sh"
    ]

    if has_download:
        score = max(score, 0.52)

    if any(token in cmd for token in suspicious_download_names):
        score = max(score, 0.60)

    if has_download and has_direct_exec:
        score += 0.22
    if "&&" in cmd:
        score += 0.06
    if ";" in cmd:
        score += 0.04

    return round(clamp01(score), 4)


def emergency_override_severity(command: str, event_type: str = "ssh") -> str:
    """
    Keep only a very small hard override list for truly dangerous payloads.
    Everything else should be score/model driven.
    """
    cmd = (command or "").strip().lower()
    normalized_type = normalize_event_type(event_type)

    if not cmd:
        return "LOW"

    if normalized_type == "web":
        critical_web = [
            "shellshock",
            "${jndi",
            "jndi:",
            "webshell",
            "shell.php",
            "cmd.php",
            "command injection",
        ]
        medium_web = [
            "union select",
            "' or 1=1",
            "\" or 1=1",
            " or 1=1",
            "<script",
            "../",
            "..\\",
            "/etc/passwd",
            "lfi",
            "rfi",
        ]
        if any(token in cmd for token in critical_web):
            return "HIGH"
        if any(token in cmd for token in medium_web):
            return "MEDIUM"
        return "LOW"

    critical_ssh = [
        "nc -e",
        "/bin/bash -i",
        "bash -i",
        "reverse shell",
        "rm -rf",
        "mkfs",
        "dd if=",
        "cat /etc/shadow",
    ]

    high_privilege = [
        "useradd ",
        "usermod ",
        "visudo",
        "/etc/sudoers",
        "backdoor",
    ]

    medium_privilege = [
        "sudo su",
        "sudo -i",
        "passwd ",
        "chpasswd",
        "crontab",
        "systemctl ",
        "service ",
    ]

    if any(token in cmd for token in critical_ssh):
        return "HIGH"

    if (
        ("wget " in cmd or "curl " in cmd or "http://" in cmd or "https://" in cmd)
        and "chmod +x" in cmd
        and "./" in cmd
    ):
        return "HIGH"

    if "| bash" in cmd or "| sh" in cmd:
        return "HIGH"

    if any(token in cmd for token in high_privilege):
        return "HIGH"

    if any(token in cmd for token in medium_privilege):
        return "MEDIUM"

    suspicious_download = [
        "wget ",
        "curl ",
        "http://",
        "https://",
        "malware.sh",
        "bot.sh",
        "payload.sh",
        "miner.sh",
        "dropper.sh",
    ]

    if any(token in cmd for token in suspicious_download):
        return "MEDIUM"

    if "cat /etc/passwd" in cmd:
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

    lstm_model_path = Path("app/lstm_ssh_v9.keras")
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
                "version": lstm_meta.get("version", "LSTM v9"),
                "accuracy": float(lstm_meta.get("accuracy", 0.0)),
                "trained_samples": int(lstm_meta.get("sessions", lstm_meta.get("trained_samples", 0))),
                "classes": int(lstm_meta.get("classes", 0)),
                "max_sequence_length": int(lstm_meta.get("max_len", lstm_meta.get("max_sequence_length", 50))),
                "max_len": int(lstm_meta.get("max_len", 50)),
                "class_names": list(lstm_meta.get("class_names", [])),
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

    app_state["hybrid_info"] = "Model-dominant hybrid engine active: LSTM + CICIoT + fallback command-risk"
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
    medium_terms = ["scan", "recon", "reconnaissance", "suspicious", "enumeration"]
    high_terms = [
        "malware", "payload", "exploit", "exploitation", "shell",
        "bruteforce", "backdoor", "attack", "privilege", "abuse"
    ]

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
        fallback_score = score_command_risk(command, event_type="ssh") * 0.35
        return {
            "lstm_session": "Unavailable",
            "session_length": len(sequence),
            "lstm_score": round(fallback_score, 4),
            "lstm_confidence": 0.0,
        }

    joined = " ; ".join(sequence).lower().strip()
    try:
        seq = lstm_tokenizer.texts_to_sequences([joined])
        lstm_cfg = app_state.get("lstm_info", {})
        max_len = int(lstm_cfg.get("max_sequence_length") or lstm_cfg.get("max_len", 50))
        padded = keras.preprocessing.sequence.pad_sequences(
            seq,
            maxlen=max_len,
            padding="post",
            truncating="post",
        )
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
        fallback_score = score_command_risk(command, event_type="ssh") * 0.35
        return {
            "lstm_session": "Fallback",
            "session_length": len(sequence),
            "lstm_score": round(fallback_score, 4),
            "lstm_confidence": 0.0,
        }


def pick_model_first_attack_class(
    *,
    event_type: str,
    raw_text: str,
    lstm_session: Optional[str],
    lstm_confidence: float,
    ciciot_attack: Optional[str],
    ciciot_confidence: float,
    ciciot_score: float,
    command_score: float,
    threat_score: float,
) -> Tuple[str, str]:
    """
    Returns: (attack_class, source)
    source in {"lstm", "ciciot", "hybrid", "fallback_rule"}
    """
    normalized_type = normalize_event_type(event_type)
    normalized_lstm = normalize_attack_label(lstm_session)
    normalized_ciciot = normalize_attack_label(ciciot_attack)

    if normalized_type == "ssh":
        if normalized_lstm and normalized_lstm != "normal" and lstm_confidence >= LSTM_HIGH_CONFIDENCE:
            return normalized_lstm, "lstm"

        if normalized_ciciot and normalized_ciciot != "normal" and ciciot_confidence >= CICIOT_HIGH_CONFIDENCE:
            return normalized_ciciot, "ciciot"

        if (
            normalized_lstm
            and normalized_lstm != "normal"
            and lstm_confidence >= LSTM_MEDIUM_CONFIDENCE
            and threat_score >= 0.45
        ):
            return normalized_lstm, "hybrid"

        if (
            normalized_ciciot
            and normalized_ciciot != "normal"
            and ciciot_confidence >= CICIOT_MEDIUM_CONFIDENCE
            and ciciot_score >= 0.55
        ):
            return normalized_ciciot, "hybrid"

        fallback = classify_ssh_attack_fallback(raw_text, lstm_session=lstm_session)
        return fallback, "fallback_rule"

    if normalized_ciciot and normalized_ciciot != "normal" and ciciot_confidence >= CICIOT_HIGH_CONFIDENCE:
        return normalized_ciciot, "ciciot"

    if normalized_ciciot and normalized_ciciot != "normal" and ciciot_confidence >= CICIOT_MEDIUM_CONFIDENCE:
        return normalized_ciciot, "hybrid"

    if normalized_lstm and normalized_lstm != "normal" and lstm_confidence >= LSTM_HIGH_CONFIDENCE and threat_score >= 0.60:
        return normalized_lstm, "lstm"

    fallback = classify_web_attack_fallback(raw_text)
    return fallback, "fallback_rule"


def fuse_hybrid_decision(
    command: str,
    session_id: str,
    event_type: str = "ssh",
    ciciot_features: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    normalized_type = normalize_event_type(event_type)

    lstm_result = predict_lstm_from_session(session_id=session_id, command=command)
    command_score = round(score_command_risk(command, event_type=normalized_type), 4)

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
    lstm_confidence = float(lstm_result.get("lstm_confidence", 0.0))
    ciciot_score = float(ciciot_result["ciciot_score"])
    ciciot_confidence = float(ciciot_result.get("ciciot_confidence", 0.0))

    if normalized_type == "ssh":
        if ciciot_features:
            threat_score = (0.50 * lstm_score) + (0.35 * ciciot_score) + (0.15 * command_score)
        else:
            threat_score = (0.75 * lstm_score) + (0.25 * command_score)
    else:
        if ciciot_features:
            threat_score = (0.65 * ciciot_score) + (0.20 * command_score) + (0.15 * lstm_score)
        else:
            threat_score = (0.45 * lstm_score) + (0.55 * command_score)

    threat_score = round(clamp01(threat_score), 4)

    attack_class, class_source = pick_model_first_attack_class(
        event_type=normalized_type,
        raw_text=command,
        lstm_session=lstm_result.get("lstm_session"),
        lstm_confidence=lstm_confidence,
        ciciot_attack=ciciot_result.get("ciciot_attack"),
        ciciot_confidence=ciciot_confidence,
        ciciot_score=ciciot_score,
        command_score=command_score,
        threat_score=threat_score,
    )

    base_severity = severity_from_score(threat_score)

    emergency_floor = emergency_override_severity(command, event_type=normalized_type)
    final_severity = max_severity(base_severity, emergency_floor)
    policy_escalated = final_severity != base_severity

    decision_source = class_source
    if class_source == "fallback_rule":
        if (
            normalized_type == "ssh"
            and lstm_confidence >= LSTM_MEDIUM_CONFIDENCE
            and normalize_attack_label(lstm_result.get("lstm_session")) not in {None, "normal"}
        ):
            decision_source = "hybrid"
        elif ciciot_score > 0.0 and ciciot_confidence >= CICIOT_MEDIUM_CONFIDENCE:
            decision_source = "hybrid"
        else:
            decision_source = "command"

    return {
        "severity": final_severity,
        "threat_score": threat_score,
        "attack_class": attack_class,
        "decision_source": decision_source,
        "fusion_method": "model_first_hybrid_lstm_ciciot_command_fallback",
        "base_severity": base_severity,
        "floor_severity": emergency_floor,
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


def get_stats_snapshot(db: Session) -> Dict[str, Any]:
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
    return get_stats_snapshot(db)


@app.post("/predict_ciciot")
def predict_ciciot_route(payload: CICIoTRequest):
    return predict_ciciot_from_dict(payload.features)


@app.post("/predict_lstm")
def predict_lstm_route(payload: LSTMPredictRequest):
    model_session_id = build_model_session_id("ssh", payload.session_id)
    return predict_lstm_from_session(model_session_id, payload.command)


@app.post("/debug_lstm")
def debug_lstm_route(payload: LSTMPredictRequest):
    model_session_id = build_model_session_id("ssh", payload.session_id)
    session_commands[model_session_id].append(payload.command)
    sequence = session_commands[model_session_id][-100:]
    joined = " ; ".join(sequence).lower().strip()

    if lstm_model is None or lstm_tokenizer is None or lstm_label_encoder is None:
        return {
            "status": "unavailable",
            "reason": "LSTM artifacts not loaded",
            "sequence": sequence,
            "joined_text": joined,
        }

    seq = lstm_tokenizer.texts_to_sequences([joined])
    lstm_cfg = app_state.get("lstm_info", {})
    max_len = int(lstm_cfg.get("max_sequence_length") or lstm_cfg.get("max_len", 50))
    padded = keras.preprocessing.sequence.pad_sequences(
        seq,
        maxlen=max_len,
        padding="post",
        truncating="post",
    )
    preds = lstm_model.predict(padded, verbose=0)[0]

    top_indices = np.argsort(preds)[::-1][:5]
    top_predictions = []
    for idx in top_indices:
        label = str(lstm_label_encoder.inverse_transform([int(idx)])[0])
        top_predictions.append({
            "label": label,
            "probability": round(float(preds[int(idx)]), 6)
        })

    return {
        "session_id": model_session_id,
        "sequence": sequence,
        "joined_text": joined,
        "token_sequence": seq[0] if seq else [],
        "nonzero_token_count": len(seq[0]) if seq else 0,
        "top_predictions": top_predictions,
        "predicted_label": top_predictions[0]["label"] if top_predictions else "unknown",
        "predicted_probability": top_predictions[0]["probability"] if top_predictions else 0.0,
    }


@app.post("/predict_hybrid")
def predict_hybrid_route(payload: HybridPredictRequest):
    model_session_id = build_model_session_id(payload.event_type, payload.session_id)
    return fuse_hybrid_decision(
        command=payload.command,
        session_id=model_session_id,
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
    stats_snapshot = get_stats_snapshot(db)

    events = db.query(Event).order_by(Event.id.desc()).limit(50).all()
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
            "total_events": stats_snapshot["total_events"],
            "ssh_count": stats_snapshot["ssh_count"],
            "web_count": stats_snapshot["web_count"],
            "high_count": stats_snapshot["high_count"],
            "avg_threat": round(avg_threat, 3),
            "bad_actors_count": stats_snapshot["bad_actors_count"],
            "policy_escalations": stats_snapshot["policy_escalations"],
            "ciciot_attack_count": stats_snapshot["ciciot_attack_count"],
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
