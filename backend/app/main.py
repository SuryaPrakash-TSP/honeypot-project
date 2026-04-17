from __future__ import annotations

from fastapi import FastAPI, Request, Depends, WebSocket, WebSocketDisconnect
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
import threading
import time
import webbrowser
import re

import pytz
import numpy as np
import joblib
from tensorflow.keras.models import load_model


# =========================
# Globals / App State
# =========================
Base = declarative_base()
IST = pytz.timezone("Asia/Kolkata")

app_state: Dict[str, Any] = {}
bad_actors: Dict[str, Dict[str, Any]] = {}

decoys_dir = Path("app/decoys")
decoys_dir.mkdir(parents=True, exist_ok=True)

dl_model = None
dl_scaler = None
dl_label_encoder = None
dl_metadata: Dict[str, Any] = {}
dl_model_dir = Path("app/models_dl")

DATABASE_URL = "sqlite:///data/events.db"
Path("data").mkdir(parents=True, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

HIGH_SEVERITY_SCORE = 0.75
MEDIUM_SEVERITY_SCORE = 0.40


# =========================
# Regex Rule Engine
# =========================
WEB_SQLI_PATTERNS = [
    re.compile(r"(?i)\bunion\s+select\b"),
    re.compile(r"(?i)(?:'|\"|\b)\s*or\s+1\s*=\s*1"),
    re.compile(r"(?i)\binformation_schema\b"),
    re.compile(r"(?i)\bsleep\s*\("),
    re.compile(r"(?i)\bbenchmark\s*\("),
    re.compile(r"(?i)\bwaitfor\s+delay\b"),
    re.compile(r"(?i)\bload_file\s*\("),
    re.compile(r"(?i)\binto\s+outfile\b"),
]

WEB_XSS_PATTERNS = [
    re.compile(r"(?i)<script[^>]*>"),
    re.compile(r"(?i)onerror\s*="),
    re.compile(r"(?i)onload\s*="),
    re.compile(r"(?i)javascript:"),
    re.compile(r"(?i)<img[^>]+onerror"),
]

WEB_TRAVERSAL_PATTERNS = [
    re.compile(r"(?i)\.\./"),
    re.compile(r"(?i)\.\.\\"),
    re.compile(r"(?i)/etc/passwd"),
    re.compile(r"(?i)/windows/win\.ini"),
]

WEB_RCE_PATTERNS = [
    re.compile(r"(?i)\bcmd\s*="),
    re.compile(r"(?i)\bexec\s*="),
    re.compile(r"(?i)\bpowershell\b"),
    re.compile(r"(?i)\bshellshock\b"),
    re.compile(r"(?i)\$\{jndi"),
    re.compile(r"(?i)\bjndi:"),
    re.compile(r"(?i)\bwget\s+https?://"),
    re.compile(r"(?i)\bcurl\s+https?://"),
]

WEB_RECON_PATTERNS = [
    re.compile(r"(?i)\bget\s+/admin\b"),
    re.compile(r"(?i)\bget\s+/administrator\b"),
    re.compile(r"(?i)\bget\s+/\.env\b"),
    re.compile(r"(?i)\bget\s+/\.git\b"),
    re.compile(r"(?i)\bget\s+/phpmyadmin\b"),
    re.compile(r"(?i)\bget\s+/wp-admin\b"),
    re.compile(r"(?i)\bget\s+/manager/html\b"),
    re.compile(r"(?i)\bnikto\b"),
    re.compile(r"(?i)\bgobuster\b"),
    re.compile(r"(?i)\bffuf\b"),
    re.compile(r"(?i)\bdirb\b"),
    re.compile(r"(?i)\bscan\b"),
    re.compile(r"(?i)\benumeration\b"),
    re.compile(r"(?i)\bprobe\b"),
]

WEB_CRED_PATTERNS = [
    re.compile(r"(?i)\bpost\s+/login\b"),
    re.compile(r"(?i)\bpost\s+/signin\b"),
    re.compile(r"(?i)\bpost\s+/auth\b"),
    re.compile(r"(?i)\bpost\s+/session\b"),
    re.compile(r"(?i)\bwp-login\b"),
    re.compile(r"(?i)\bxmlrpc\.php\b"),
    re.compile(r"(?i)\bcredential stuffing\b"),
    re.compile(r"(?i)\bbrute\s*force\b"),
    re.compile(r"(?i)\bfailed login\b"),
    re.compile(r"(?i)\binvalid password\b"),
]

WEB_DDOS_PATTERNS = [
    re.compile(r"(?i)\bhttp flood\b"),
    re.compile(r"(?i)\budp flood\b"),
    re.compile(r"(?i)\bsyn flood\b"),
    re.compile(r"(?i)\back flood\b"),
    re.compile(r"(?i)\bicmp flood\b"),
    re.compile(r"(?i)\bslowloris\b"),
    re.compile(r"(?i)\btoo many requests\b"),
    re.compile(r"(?i)\brate limit exceeded\b"),
    re.compile(r"(?i)\btraffic spike\b"),
    re.compile(r"(?i)\bflood\b"),
]

SSH_DESTRUCTIVE_PATTERNS = [
    re.compile(r"(?i)\brm\s+-rf\b"),
    re.compile(r"(?i)\bmkfs\b"),
    re.compile(r"(?i)\bdd\s+if="),
    re.compile(r"(?i)\bshred\b"),
    re.compile(r"(?i)\btruncate\b"),
]

SSH_PRIV_PATTERNS = [
    re.compile(r"(?i)\bsudo\b"),
    re.compile(r"(?i)\bsu\b"),
    re.compile(r"(?i)\bpasswd\b"),
    re.compile(r"(?i)\buseradd\b"),
    re.compile(r"(?i)\busermod\b"),
    re.compile(r"(?i)\bvisudo\b"),
    re.compile(r"(?i)/etc/sudoers"),
    re.compile(r"(?i)\bchpasswd\b"),
    re.compile(r"(?i)\bcrontab\b"),
    re.compile(r"(?i)\bsystemctl\b"),
    re.compile(r"(?i)\bservice\b"),
]

SSH_CRED_PATTERNS = [
    re.compile(r"(?i)\bhydra\b"),
    re.compile(r"(?i)\bmedusa\b"),
    re.compile(r"(?i)\bpatator\b"),
    re.compile(r"(?i)\bhashcat\b"),
    re.compile(r"(?i)\bjohn\b"),
    re.compile(r"(?i)/etc/shadow"),
    re.compile(r"(?i)\bcredential"),
]

SSH_EXPLOIT_PATTERNS = [
    re.compile(r"(?i)\bwget\s+https?://"),
    re.compile(r"(?i)\bcurl\s+https?://"),
    re.compile(r"(?i)\bchmod\s+\+x\b"),
    re.compile(r"(?i)\|\s*bash\b"),
    re.compile(r"(?i)\|\s*sh\b"),
    re.compile(r"(?i)\bbash\s+-i\b"),
    re.compile(r"(?i)/bin/bash\s+-i"),
    re.compile(r"(?i)\bpython\s+-c\b"),
    re.compile(r"(?i)\bperl\s+-e\b"),
    re.compile(r"(?i)\bnc\s+-e\b"),
    re.compile(r"(?i)\bnohup\b"),
    re.compile(r"(?i)\breverse shell\b"),
    re.compile(r"(?i)\bpayload\b"),
    re.compile(r"(?i)\bbackdoor\b"),
]

SSH_RECON_PATTERNS = [
    re.compile(r"(?i)\buname\s+-a\b"),
    re.compile(r"(?i)\bnetstat\b"),
    re.compile(r"(?i)\bss\s"),
    re.compile(r"(?i)\bifconfig\b"),
    re.compile(r"(?i)\bip\s+a\b"),
    re.compile(r"(?i)\bwhois\b"),
    re.compile(r"(?i)\bdig\b"),
    re.compile(r"(?i)\bnslookup\b"),
    re.compile(r"(?i)\blsb_release\b"),
    re.compile(r"(?i)/etc/os-release"),
    re.compile(r"(?i)\bps aux\b"),
    re.compile(r"(?i)\bps -ef\b"),
    re.compile(r"(?i)/etc/passwd"),
    re.compile(r"(?i)\bnmap\b"),
    re.compile(r"(?i)\bmasscan\b"),
    re.compile(r"(?i)\bnikto\b"),
    re.compile(r"(?i)\benum4linux\b"),
    re.compile(r"(?i)\bscan\b"),
    re.compile(r"(?i)\brecon\b"),
]


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
    event_type = Column(String, default="network")

    command = Column(String, default="")
    attack_class = Column(String, default="normal")
    reason = Column(String, default="benign_activity")

    severity = Column(String, default="LOW")
    threat_score = Column(Float, default=0.0)

    lstm_session = Column(String, default="Removed")
    lstm_score = Column(Float, default=0.0)
    command_score = Column(Float, default=0.0)

    ciciot_attack = Column(String, nullable=True)
    ciciot_confidence = Column(Float, default=0.0)
    ciciot_score = Column(Float, default=0.0)

    decision_source = Column(String, default="placeholder")
    fusion_method = Column(String, default="single_dl_placeholder")

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
        "lstm_session": "ALTER TABLE events ADD COLUMN lstm_session VARCHAR DEFAULT 'Removed'",
        "lstm_score": "ALTER TABLE events ADD COLUMN lstm_score FLOAT DEFAULT 0.0",
        "command_score": "ALTER TABLE events ADD COLUMN command_score FLOAT DEFAULT 0.0",
        "ciciot_score": "ALTER TABLE events ADD COLUMN ciciot_score FLOAT DEFAULT 0.0",
        "fusion_method": "ALTER TABLE events ADD COLUMN fusion_method VARCHAR DEFAULT 'single_dl_placeholder'",
        "base_severity": "ALTER TABLE events ADD COLUMN base_severity VARCHAR DEFAULT 'LOW'",
        "floor_severity": "ALTER TABLE events ADD COLUMN floor_severity VARCHAR DEFAULT 'LOW'",
        "policy_escalated": "ALTER TABLE events ADD COLUMN policy_escalated BOOLEAN DEFAULT 0",
        "action_taken": "ALTER TABLE events ADD COLUMN action_taken VARCHAR DEFAULT 'logged'",
        "reason": "ALTER TABLE events ADD COLUMN reason VARCHAR DEFAULT 'benign_activity'",
    }

    with engine.begin() as conn:
        for col_name, stmt in alter_statements.items():
            if col_name not in columns:
                conn.execute(text(stmt))


# =========================
# Pydantic Models
# =========================
class DLFeatureRequest(BaseModel):
    features: Dict[str, Any]


class NetworkIngestRequest(BaseModel):
    ip: str = Field(..., description="Source IP address")
    session_id: str = "network"
    event_type: str = "network"
    activity: str = Field(..., description="Network activity summary")
    username: str = "net-anon"
    features: Optional[Dict[str, Any]] = None


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


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def severity_rank(severity: str) -> int:
    mapping = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    return mapping.get((severity or "LOW").upper(), 1)


def normalize_severity(severity: str) -> str:
    sev = (severity or "LOW").upper()
    return sev if sev in {"LOW", "MEDIUM", "HIGH"} else "LOW"


def normalize_event_type(event_type: Optional[str], default: str = "network") -> str:
    value = (event_type or default).strip().lower()
    return value if value in {"web", "network"} else default


def severity_from_score(score: float) -> str:
    if score >= HIGH_SEVERITY_SCORE:
        return "HIGH"
    if score >= MEDIUM_SEVERITY_SCORE:
        return "MEDIUM"
    return "LOW"


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def regex_hit_count(patterns: List[re.Pattern], text_value: str) -> int:
    text_value = text_value or ""
    return sum(1 for pattern in patterns if pattern.search(text_value))


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
            
def load_dl_artifacts() -> Dict[str, Any]:
    global dl_model, dl_scaler, dl_label_encoder, dl_metadata

    model_path = dl_model_dir / "cicids_dl_model.keras"
    scaler_path = dl_model_dir / "scaler.pkl"
    encoder_path = dl_model_dir / "label_encoder.pkl"
    metadata_path = dl_model_dir / "dl_metadata.json"

    missing = []
    for path in [model_path, scaler_path, encoder_path, metadata_path]:
        if not path.exists():
            missing.append(str(path))

    if missing:
        raise FileNotFoundError(f"Missing DL artifacts: {missing}")

    dl_model = load_model(model_path)
    dl_scaler = joblib.load(scaler_path)
    dl_label_encoder = joblib.load(encoder_path)

    with open(metadata_path, "r", encoding="utf-8") as f:
        dl_metadata = json.load(f)

    feature_columns = dl_metadata.get("feature_names", [])

    app_state["dl_model"] = "loaded"
    app_state["dl_feature_columns"] = feature_columns
    app_state["dl_info"] = {
        "status": "loaded",
        "type": "single_cicids2017_deep_learning_model",
        "model_path": str(model_path),
        "scaler_path": str(scaler_path),
        "label_encoder_path": str(encoder_path),
        "metadata_path": str(metadata_path),
        "feature_count": len(feature_columns),
        "class_names": list(getattr(dl_label_encoder, "classes_", [])),
    }

    return app_state["dl_info"]


def get_required_feature_columns() -> List[str]:
    return app_state.get("dl_feature_columns", []) or dl_metadata.get("feature_names", [])


def prepare_dl_features(feature_dict: Dict[str, Any]) -> np.ndarray:
    if dl_scaler is None:
        raise RuntimeError("DL scaler is not loaded")

    feature_columns = get_required_feature_columns()
    if not feature_columns:
        raise RuntimeError("DL feature columns are not available")

    row = []
    missing = []

    for col in feature_columns:
        if col not in feature_dict:
            missing.append(col)
            row.append(0.0)
        else:
            try:
                row.append(float(feature_dict[col]))
            except Exception:
                row.append(0.0)

    if missing:
        print(f"Warning: missing features replaced with 0.0 -> {missing[:10]}{'...' if len(missing) > 10 else ''}")

    arr = np.array([row], dtype=np.float32)
    scaled = dl_scaler.transform(arr)
    return scaled


def map_attack_to_severity(predicted_class: str, confidence: float) -> str:
    label = (predicted_class or "Benign").strip().lower()

    if label == "benign":
        return "LOW"

    if label in {"ddos", "dos", "bot", "portscan"}:
        return "HIGH" if confidence >= 0.80 else "MEDIUM"

    if label in {"bruteforce", "infiltration", "web attack"}:
        return "HIGH" if confidence >= 0.70 else "MEDIUM"

    return "MEDIUM" if confidence >= 0.50 else "LOW"


def map_attack_to_reason(predicted_class: str) -> str:
    label = (predicted_class or "Benign").strip().lower()

    mapping = {
        "benign": "benign_network_activity",
        "bot": "botnet_like_network_activity",
        "ddos": "distributed_denial_of_service_detected",
        "dos": "denial_of_service_detected",
        "bruteforce": "brute_force_pattern_detected",
        "portscan": "network_reconnaissance_detected",
        "infiltration": "infiltration_pattern_detected",
        "web attack": "web_attack_pattern_detected",
    }
    return mapping.get(label, "intrusion_pattern_detected")            


# =========================
# Rule Engine
# =========================
def classify_web_attack_fallback(activity: str) -> str:
    text_value = (activity or "").strip().lower()

    if not text_value:
        return "normal"

    if regex_hit_count(WEB_DDOS_PATTERNS, text_value) > 0:
        return "ddos"
    if regex_hit_count(WEB_RCE_PATTERNS, text_value) > 0:
        return "exploitation"
    if regex_hit_count(WEB_SQLI_PATTERNS, text_value) > 0:
        return "web_attack"
    if regex_hit_count(WEB_XSS_PATTERNS, text_value) > 0:
        return "web_attack"
    if regex_hit_count(WEB_TRAVERSAL_PATTERNS, text_value) > 0:
        return "web_attack"
    if regex_hit_count(WEB_CRED_PATTERNS, text_value) > 0:
        return "credential_attack"
    if regex_hit_count(WEB_RECON_PATTERNS, text_value) > 0:
        return "reconnaissance"

    return "normal"


def infer_reason(
    *,
    event_type: str,
    raw_text: str,
    attack_class: str,
    decision_source: str,
    severity: str,
    policy_escalated: bool,
) -> str:
    text_value = (raw_text or "").strip().lower()
    normalized_type = normalize_event_type(event_type)
    normalized_attack = (attack_class or "normal").lower()

    if policy_escalated and decision_source == "policy":
        return "policy_escalation_or_rate_limit_trigger"

    if normalized_type in {"web", "network"}:
        if regex_hit_count(WEB_SQLI_PATTERNS, text_value) > 0:
            return "sql_injection_attempt"
        if regex_hit_count(WEB_XSS_PATTERNS, text_value) > 0:
            return "cross_site_scripting_attempt"
        if regex_hit_count(WEB_TRAVERSAL_PATTERNS, text_value) > 0:
            return "path_traversal_or_file_probe"
        if regex_hit_count(WEB_RCE_PATTERNS, text_value) > 0:
            return "remote_command_execution_attempt"
        if regex_hit_count(WEB_RECON_PATTERNS, text_value) > 0:
            return "endpoint_enumeration"
        if regex_hit_count(WEB_CRED_PATTERNS, text_value) > 0:
            return "credential_or_login_attack"
        if regex_hit_count(WEB_DDOS_PATTERNS, text_value) > 0:
            return "request_flood_or_rate_abuse"
        if normalized_attack == "reconnaissance":
            return "network_or_web_reconnaissance"
        if normalized_attack == "web_attack":
            return "web_injection_pattern"
        if normalized_attack == "exploitation":
            return "exploitation_attempt"
        if normalized_attack == "ddos":
            return "network_flood_pattern"
        return "single_dl_model_not_integrated_yet"

    return "single_dl_model_not_integrated_yet"


def score_command_risk(command: str, event_type: str = "network") -> float:
    text_value = (command or "").strip().lower()
    normalized_type = normalize_event_type(event_type)

    if not text_value:
        return 0.0

    score = 0.06

    if normalized_type in {"web", "network"}:
        if text_value.startswith("get /"):
            score = max(score, 0.18)

        if regex_hit_count(WEB_RECON_PATTERNS, text_value) > 0:
            score = max(score, 0.42)

        if regex_hit_count(WEB_CRED_PATTERNS, text_value) > 0:
            score = max(score, 0.35)

        if regex_hit_count(WEB_SQLI_PATTERNS, text_value) > 0:
            score = max(score, 0.72)

        if regex_hit_count(WEB_XSS_PATTERNS, text_value) > 0:
            score = max(score, 0.65)

        if regex_hit_count(WEB_TRAVERSAL_PATTERNS, text_value) > 0:
            score = max(score, 0.70)

        if regex_hit_count(WEB_RCE_PATTERNS, text_value) > 0:
            score = max(score, 0.86)

        if regex_hit_count(WEB_DDOS_PATTERNS, text_value) > 0:
            score = max(score, 0.80)

    return round(clamp01(score), 4)


def emergency_override_severity(command: str, event_type: str = "network") -> str:
    text_value = (command or "").strip().lower()
    normalized_type = normalize_event_type(event_type)

    if not text_value:
        return "LOW"

    if normalized_type in {"web", "network"}:
        if regex_hit_count(WEB_RCE_PATTERNS, text_value) > 0:
            return "HIGH"
        if regex_hit_count(WEB_SQLI_PATTERNS, text_value) > 0:
            return "MEDIUM"
        if regex_hit_count(WEB_TRAVERSAL_PATTERNS, text_value) > 0:
            return "MEDIUM"
        if regex_hit_count(WEB_XSS_PATTERNS, text_value) > 0:
            return "MEDIUM"
        if regex_hit_count(WEB_DDOS_PATTERNS, text_value) > 0:
            return "HIGH"

    return "LOW"


def severity_floor_from_attack_class(attack_class: str, command_score: float, event_type: str) -> str:
    attack = (attack_class or "normal").lower()

    if attack in {"exploitation", "ddos"}:
        return "HIGH"

    if attack in {"credential_attack", "web_attack", "reconnaissance"}:
        return "MEDIUM"

    if command_score >= 0.88:
        return "HIGH"
    if command_score >= 0.40:
        return "MEDIUM"

    return "LOW"


# =========================
# Rate Limiting / Actor Escalation
# =========================
class RateLimiter:
    def __init__(self, max_requests: int = 12, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)

    def check(self, ip: str) -> Dict[str, Any]:
        now_value = time.time()
        q = self.requests[ip]

        while q and (now_value - q[0] > self.window_seconds):
            q.popleft()

        q.append(now_value)
        blocked = len(q) > self.max_requests

        return {
            "count": len(q),
            "window_seconds": self.window_seconds,
            "blocked": blocked,
        }


rate_limiter = RateLimiter(max_requests=12, window_seconds=60)


def update_bad_actor_state(ip: str, event_payload: Dict[str, Any]) -> Dict[str, Any]:
    severity = normalize_severity(event_payload.get("severity", "LOW"))
    threat_score = float(event_payload.get("threat_score", 0.0))
    attack_class = event_payload.get("attack_class") or "BENIGN"

    normalized_attack = str(attack_class).strip().lower()
    is_attack = normalized_attack not in {"benign", "normal"}

    state = bad_actors.setdefault(
        ip,
        {
            "high_alerts": 0,
            "medium_alerts": 0,
            "malicious_events": 0,
            "latest_severity": "LOW",
            "last_attack": "BENIGN",
            "max_threat_score": 0.0,
            "enforcement": "monitor",
            "last_seen": None,
        },
    )

    # Update counters only for actual attacks
    if is_attack and severity == "HIGH":
        state["high_alerts"] += 1

    if is_attack and severity in {"MEDIUM", "HIGH"}:
        state["medium_alerts"] += 1

    if is_attack or severity in {"MEDIUM", "HIGH"} or threat_score >= 0.40:
        state["malicious_events"] += 1

    # Update max threat score only for attacks
    if is_attack:
        state["max_threat_score"] = max(
            float(state.get("max_threat_score", 0.0)),
            threat_score,
        )

    # Always update latest info
    state["latest_severity"] = severity
    state["last_attack"] = attack_class
    state["last_seen"] = now_utc().isoformat()

    # Enforcement logic
    if state["high_alerts"] >= 3:
        state["enforcement"] = "blocked"
    elif state["malicious_events"] >= 3:
        state["enforcement"] = "rate_limited"
    elif state["medium_alerts"] >= 2 or state["high_alerts"] >= 1:
        state["enforcement"] = "escalated"
    else:
        state["enforcement"] = "monitor"

    return state


def rebuild_bad_actor_state_from_db(db: Session) -> None:
    global bad_actors
    bad_actors.clear()

    events = db.query(Event).order_by(Event.timestamp.asc(), Event.id.asc()).all()

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

    try:
        dl_info = load_dl_artifacts()
        app_state["hybrid_info"] = "Single CICIDS2017 deep learning model active"
        print("DL model loaded successfully")
        print(dl_info)
    except Exception as e:
        app_state["dl_model"] = None
        app_state["dl_feature_columns"] = []
        app_state["dl_info"] = {
            "status": "error",
            "type": "single_cicids2017_deep_learning_model",
            "reason": str(e),
        }
        app_state["hybrid_info"] = "Single DL model failed to load"
        print(f"DL model loading failed: {e}")

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
# Single DL Placeholder
# =========================
def predict_dl_from_features(
    feature_dict: Optional[Dict[str, Any]] = None,
    raw_text: str = "",
    event_type: str = "network",
) -> Dict[str, Any]:
    if dl_model is None or dl_scaler is None or dl_label_encoder is None:
        raise RuntimeError("DL model artifacts are not loaded")

    if not feature_dict:
        raise ValueError("Feature dictionary is required for DL prediction")

    scaled_features = prepare_dl_features(feature_dict)

    predictions = dl_model.predict(scaled_features, verbose=0)
    probs = predictions[0]

    predicted_index = int(np.argmax(probs))
    predicted_class = str(dl_label_encoder.inverse_transform([predicted_index])[0])
    confidence = float(probs[predicted_index])

    attack_class = predicted_class
    severity = map_attack_to_severity(predicted_class, confidence)
    reason = map_attack_to_reason(predicted_class)
    is_attack = predicted_class.strip().lower() != "benign"

    if is_attack:
        threat_score = confidence
    else:
        threat_score = 0.0

    return {
        "severity": severity,
        "threat_score": round(threat_score, 4),
        "attack_class": attack_class,
        "predicted_class": predicted_class,
        "confidence": round(confidence, 4),
        "is_attack": is_attack,
        "reason": reason,
        "decision_source": "single_dl_model",
        "base_severity": severity,
        "floor_severity": severity,
        "policy_escalated": False,
        "class_probabilities": {
            str(cls): round(float(prob), 4)
            for cls, prob in zip(dl_label_encoder.classes_, probs)
        },
    }


def apply_enforcement(ip: str, severity: str, rl_result: Dict[str, Any], actor_state: Dict[str, Any]) -> str:
    severity = normalize_severity(severity)
    enforcement = actor_state.get("enforcement", "monitor")

    if rl_result["blocked"]:
        return "rate_limited"
    if enforcement == "blocked":
        return "blocked"
    if enforcement == "rate_limited":
        return "rate_limited"
    if enforcement == "escalated":
        return "alerted"
    if severity == "HIGH":
        return "alerted"
    if severity == "MEDIUM":
        return "monitored"
    return "logged"


def serialize_event(event: Event) -> Dict[str, Any]:
    predicted_class = event.ciciot_attack or event.attack_class or "BENIGN"
    confidence = round(float(event.ciciot_confidence or event.threat_score or 0.0), 4)

    return {
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "timestamp_formatted": format_time(event.timestamp),
        "session_id": event.session_id,
        "source_ip": event.source_ip,
        "username": event.username,
        "event_type": normalize_event_type(event.event_type),
        "activity": event.command or "",
        "attack_class": event.attack_class or "BENIGN",
        "predicted_class": predicted_class,
        "confidence": confidence,
        "is_attack": (predicted_class or "").strip().lower() != "benign",
        "reason": event.reason or "benign_network_activity",
        "severity": normalize_severity(event.severity),
        "threat_score": round(float(event.threat_score or 0.0), 4),
        "decision_source": event.decision_source or "single_dl_model",
        "base_severity": normalize_severity(event.base_severity or "LOW"),
        "floor_severity": normalize_severity(event.floor_severity or "LOW"),
        "policy_escalated": bool(event.policy_escalated),
        "action_taken": event.action_taken or "logged",
    }


def get_stats_snapshot(db: Session) -> Dict[str, Any]:
    normalized_event_type = func.lower(func.trim(Event.event_type))
    normalized_severity = func.upper(func.trim(Event.severity))

    total_events = db.query(Event).count()
    web_count = db.query(Event).filter(normalized_event_type == "web").count()
    network_count = db.query(Event).filter(normalized_event_type == "network").count()
    high_count = db.query(Event).filter(normalized_severity == "HIGH").count()
    medium_count = db.query(Event).filter(normalized_severity == "MEDIUM").count()
    low_count = db.query(Event).filter(normalized_severity == "LOW").count()

    attack_count = (
        db.query(Event)
        .filter(Event.attack_class.isnot(None))
        .filter(func.lower(func.trim(Event.attack_class)).notin_(["normal", "benign"]))
        .count()
    )
    escalated_count = db.query(Event).filter(Event.policy_escalated == True).count()  # noqa: E712

    return {
        "total_events": total_events,
        "ssh_count": 0,
        "web_count": web_count,
        "network_count": network_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "attack_count": attack_count,
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
    feature_dict: Optional[Dict[str, Any]],
):
    normalized_type = normalize_event_type(event_type, default=event_type or "network")

    prediction = predict_dl_from_features(
        feature_dict=feature_dict,
        raw_text=raw_text,
        event_type=normalized_type,
    )

    rl_result = rate_limiter.check(ip)
    if rl_result["blocked"]:
        prediction["severity"] = max_severity(prediction["severity"], "HIGH")
        prediction["policy_escalated"] = True
        prediction["base_severity"] = prediction.get("base_severity", prediction["severity"])
        prediction["floor_severity"] = max_severity(
            prediction.get("floor_severity", "LOW"),
            "HIGH",
        )
        prediction["decision_source"] = "policy"
        prediction["reason"] = "policy_escalation_or_rate_limit_trigger"

    actor_preview = update_bad_actor_state(
        ip,
        {
            "severity": prediction["severity"],
            "threat_score": prediction["threat_score"],
            "attack_class": prediction["attack_class"],
        },
    )

    if actor_preview["enforcement"] in {"escalated", "rate_limited", "blocked"}:
        prediction["policy_escalated"] = True
        prediction["decision_source"] = "policy"
        prediction["reason"] = "policy_escalation_or_rate_limit_trigger"

        if actor_preview["enforcement"] in {"rate_limited", "blocked"}:
            prediction["severity"] = max_severity(prediction["severity"], "HIGH")
            prediction["floor_severity"] = max_severity(
                prediction.get("floor_severity", "LOW"),
                "HIGH",
            )

    action_taken = apply_enforcement(
        ip=ip,
        severity=prediction["severity"],
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

    attack_class=prediction["attack_class"],
    reason=prediction["reason"],
    severity=normalize_severity(prediction["severity"]),
    threat_score=float(prediction["threat_score"]),

    # Clean DL mapping
    lstm_session="Removed",
    lstm_score=0.0,
    command_score=0.0,

    ciciot_attack=prediction["predicted_class"],
    ciciot_confidence=float(prediction["confidence"]),
    ciciot_score=float(prediction["confidence"]),

    decision_source=prediction["decision_source"],
    fusion_method="single_dl",

    base_severity=normalize_severity(prediction["base_severity"]),
    floor_severity=normalize_severity(prediction["floor_severity"]),
    policy_escalated=bool(prediction["policy_escalated"]),

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
        "ingest_routes": ["/ingest_network"],
        "predict_routes": ["/predict_dl"],
    }


@app.get("/model-info")
def model_info():
    return {
        "model_runtime": "single_cicids2017_deep_learning_model",
        "dl_info": app_state.get("dl_info", {}),
    }


@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    return get_stats_snapshot(db)


@app.post("/predict_dl")
def predict_dl_route(payload: DLFeatureRequest):
    return predict_dl_from_features(
        feature_dict=payload.features,
        raw_text="",
        event_type="network",
    )


@app.post("/ingest_network")
async def ingest_network(payload: NetworkIngestRequest, db: Session = Depends(get_db)):
    return await ingest_event_common(
        db=db,
        ip=payload.ip,
        username=payload.username,
        raw_text=payload.activity,
        session_id=payload.session_id,
        event_type="network",
        feature_dict=payload.features,
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
            "network_count": stats_snapshot["network_count"],
            "high_count": stats_snapshot["high_count"],
            "avg_threat": round(avg_threat, 3),
            "bad_actors_count": stats_snapshot["bad_actors_count"],
            "policy_escalations": stats_snapshot["policy_escalations"],
            "attack_count": stats_snapshot["attack_count"],
            "live_count": live_count,
            "visible_high": visible_high,
            "dl_info": app_state.get("dl_info", {}),

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
