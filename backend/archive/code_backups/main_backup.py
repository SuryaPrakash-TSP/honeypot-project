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
import re

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
# Decision Tuning
# =========================
LSTM_HIGH_CONFIDENCE = 0.75
LSTM_MEDIUM_CONFIDENCE = 0.40
LSTM_LOW_CONFIDENCE = 0.25

CICIOT_HIGH_CONFIDENCE = 0.80
CICIOT_MEDIUM_CONFIDENCE = 0.60
CICIOT_LOW_CONFIDENCE = 0.35

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
    event_type = Column(String, default="ssh")

    command = Column(String, default="")
    attack_class = Column(String, default="normal")
    reason = Column(String, default="benign_activity")

    severity = Column(String, default="LOW")
    threat_score = Column(Float, default=0.0)

    lstm_session = Column(String, default="Unknown")
    lstm_score = Column(Float, default=0.0)
    command_score = Column(Float, default=0.0)

    ciciot_attack = Column(String, nullable=True)
    ciciot_confidence = Column(Float, default=0.0)
    ciciot_score = Column(Float, default=0.0)

    decision_source = Column(String, default="rules")
    fusion_method = Column(String, default="adaptive_hybrid_lstm_ciciot_command")

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
        "fusion_method": "ALTER TABLE events ADD COLUMN fusion_method VARCHAR DEFAULT 'adaptive_hybrid_lstm_ciciot_command'",
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
    return value if value in {"ssh", "web"} else default


def severity_from_score(score: float) -> str:
    if score >= HIGH_SEVERITY_SCORE:
        return "HIGH"
    if score >= MEDIUM_SEVERITY_SCORE:
        return "MEDIUM"
    return "LOW"


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def build_model_session_id(event_type: str, session_id: str) -> str:
    normalized_type = normalize_event_type(event_type, default="ssh")
    raw_session = (session_id or normalized_type).strip()
    return f"{normalized_type}:{raw_session}"


def regex_hit_count(patterns: List[re.Pattern], text_value: str) -> int:
    text_value = text_value or ""
    return sum(1 for pattern in patterns if pattern.search(text_value))


def normalize_attack_label(raw_label: Optional[str]) -> Optional[str]:
    if raw_label is None:
        return None

    label = str(raw_label).strip().lower()
    if not label:
        return None

    if label in {"benign", "normal", "harmless", "none", "unknown", "unavailable", "fallback"}:
        return "normal"

    if any(term in label for term in ["ddos", "dos", "syn flood", "udp flood", "icmp flood", "ack flood", "http flood", "flood"]):
        return "ddos"

    if any(term in label for term in ["scan", "recon", "reconnaissance", "portscan", "port scan", "enumeration", "discovery"]):
        return "reconnaissance"

    if any(term in label for term in ["bruteforce", "brute force", "credential"]):
        return "credential_attack"

    if any(term in label for term in ["privilege", "sudo", "escalation", "privilege_abuse"]):
        return "privilege_abuse"

    if any(term in label for term in ["destructive", "wiper", "rm -rf", "shred", "mkfs"]):
        return "destructive_activity"

    if any(term in label for term in ["exploit", "malware", "backdoor", "rce", "injection", "shell", "payload", "exploitation"]):
        return "exploitation"

    if any(term in label for term in ["bot", "botnet", "c2", "command and control"]):
        return "botnet_activity"

    if "web" in label:
        return "web_attack"

    return label.replace(" ", "_")


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
        if regex_hit_count(WEB_SQLI_PATTERNS, text_value) > 0:
            return "web_attack"
        return "credential_attack"

    if regex_hit_count(WEB_RECON_PATTERNS, text_value) > 0:
        return "reconnaissance"

    if text_value.startswith("get /"):
        return "reconnaissance"

    return "normal"


def get_explicit_ssh_command_class(command: str) -> Optional[str]:
    cmd = (command or "").strip().lower()
    if not cmd:
        return "normal"

    exact_benign = {"ls", "pwd", "whoami", "id", "date", "clear", "history", "hostname"}
    benign_prefixes = ["echo ", "cd ", "ls "]

    if cmd in exact_benign or any(cmd.startswith(prefix) for prefix in benign_prefixes):
        return "normal"

    if regex_hit_count(SSH_DESTRUCTIVE_PATTERNS, cmd) > 0:
        return "destructive_activity"

    if regex_hit_count(SSH_PRIV_PATTERNS, cmd) > 0:
        return "privilege_abuse"

    if regex_hit_count(SSH_CRED_PATTERNS, cmd) > 0:
        return "credential_attack"

    if regex_hit_count(SSH_EXPLOIT_PATTERNS, cmd) > 0:
        return "exploitation"

    if regex_hit_count(SSH_RECON_PATTERNS, cmd) > 0:
        return "reconnaissance"

    compound_recon_markers = ["whoami", "pwd", "id", "uname", "hostname", "env", "printenv"]
    recon_hits = sum(1 for marker in compound_recon_markers if marker in cmd)
    if recon_hits >= 2 and ("&&" in cmd or ";" in cmd):
        return "reconnaissance"

    return None


def classify_ssh_attack_fallback(command: str, lstm_session: Optional[str] = None) -> str:
    cmd = (command or "").strip().lower()

    explicit = get_explicit_ssh_command_class(cmd)
    if explicit is not None:
        return explicit

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

    if normalized_type == "web":
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
            return "web_endpoint_reconnaissance"
        if normalized_attack == "web_attack":
            return "web_injection_pattern"
        if normalized_attack == "exploitation":
            return "web_exploitation_attempt"
        return "routine_web_activity"

    if normalized_attack == "normal":
        return "benign_shell_command"

    if "sudo su" in text_value or "sudo -i" in text_value or text_value == "su" or text_value.startswith("su "):
        return "privilege_escalation_attempt"
    if text_value.startswith("useradd ") or text_value.startswith("usermod ") or "backdoor" in text_value:
        return "persistence_backdoor_creation"
    if text_value.startswith("passwd ") or "chpasswd" in text_value:
        return "credential_reset_or_account_modification"
    if "cat /etc/shadow" in text_value:
        return "credential_dump_attempt"
    if "rm -rf" in text_value or "mkfs" in text_value or "dd if=" in text_value:
        return "destructive_system_command"
    if ("wget " in text_value or "curl " in text_value) and ("http://" in text_value or "https://" in text_value):
        if "chmod +x" in text_value or "./" in text_value or "| bash" in text_value or "| sh" in text_value:
            return "malicious_download_and_execution"
        return "suspicious_file_download"
    if "chmod +x" in text_value:
        return "payload_permission_change"
    if "./" in text_value or "| bash" in text_value or "| sh" in text_value or "bash -i" in text_value or "/bin/bash -i" in text_value:
        return "payload_execution_attempt"
    if regex_hit_count(SSH_RECON_PATTERNS, text_value) > 0:
        return "system_information_reconnaissance"
    if "cat /etc/passwd" in text_value:
        return "account_enumeration"
    if normalized_attack == "credential_attack":
        return "credential_access_attempt"
    if normalized_attack == "privilege_abuse":
        return "privileged_account_abuse"
    if normalized_attack == "reconnaissance":
        return "system_reconnaissance"
    if normalized_attack == "exploitation":
        return "malicious_execution_chain"
    if normalized_attack == "destructive_activity":
        return "destructive_activity_detected"

    return "suspicious_activity_detected"


def score_command_risk(command: str, event_type: str = "ssh") -> float:
    text_value = (command or "").strip().lower()
    normalized_type = normalize_event_type(event_type)

    if not text_value:
        return 0.0

    if normalized_type == "web":
        score = 0.06

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

    exact_benign = {"ls", "pwd", "whoami", "id", "date", "clear", "history", "hostname", "uname"}
    benign_prefixes = ["echo ", "cd ", "ls "]

    compound_recon_markers = ["whoami", "pwd", "id", "uname", "hostname", "env", "printenv"]
    recon_hits = sum(1 for marker in compound_recon_markers if marker in text_value)
    if recon_hits >= 2 and ("&&" in text_value or ";" in text_value):
        return 0.30

    if text_value in exact_benign or any(text_value.startswith(prefix) for prefix in benign_prefixes):
        return 0.03

    score = 0.12

    if regex_hit_count(SSH_RECON_PATTERNS, text_value) > 0:
        score = max(score, 0.24)

    if "cat /etc/passwd" in text_value:
        score = max(score, 0.38)

    if regex_hit_count(SSH_PRIV_PATTERNS, text_value) > 0:
        score = max(score, 0.58)

    if "sudo su" in text_value or "sudo -i" in text_value or text_value == "su" or text_value.startswith("su "):
        score = max(score, 0.72)

    if text_value.startswith("useradd ") or text_value.startswith("usermod "):
        score = max(score, 0.88)

    if "passwd " in text_value or "chpasswd" in text_value:
        score = max(score, 0.86)

    if "/etc/sudoers" in text_value or "visudo" in text_value:
        score = max(score, 0.90)

    if "cat /etc/shadow" in text_value:
        score = max(score, 0.95)

    if regex_hit_count(SSH_CRED_PATTERNS, text_value) > 0:
        score = max(score, 0.68)

    if regex_hit_count(SSH_EXPLOIT_PATTERNS, text_value) > 0:
        score = max(score, 0.62)

    if regex_hit_count(SSH_DESTRUCTIVE_PATTERNS, text_value) > 0:
        score = max(score, 0.95)

    has_download = bool(re.search(r"(?i)\b(wget|curl)\b", text_value)) and bool(re.search(r"(?i)https?://", text_value))
    has_permission_change = "chmod +x" in text_value
    has_direct_exec = any(token in text_value for token in ["./", "bash ", "sh ", "python -c", "perl -e", "nohup"])
    has_pipe_exec = "| bash" in text_value or "| sh" in text_value
    has_reverse_shell = any(token in text_value for token in ["nc -e", "/bin/bash -i", "bash -i", "python -c", "perl -e", "reverse shell"])
    has_destructive = regex_hit_count(SSH_DESTRUCTIVE_PATTERNS, text_value) > 0
    has_credential_access = "cat /etc/shadow" in text_value

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

    suspicious_download_names = ["malware.sh", "bot.sh", "payload.sh", "miner.sh", "dropper.sh"]
    if has_download:
        score = max(score, 0.54)

    if any(token in text_value for token in suspicious_download_names):
        score = max(score, 0.64)

    if has_download and has_direct_exec:
        score = max(score, 0.84)

    if "&&" in text_value:
        score += 0.05
    if ";" in text_value:
        score += 0.03

    return round(clamp01(score), 4)


def emergency_override_severity(command: str, event_type: str = "ssh") -> str:
    text_value = (command or "").strip().lower()
    normalized_type = normalize_event_type(event_type)

    if not text_value:
        return "LOW"

    if normalized_type == "web":
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

    if regex_hit_count(SSH_DESTRUCTIVE_PATTERNS, text_value) > 0:
        return "HIGH"

    if "cat /etc/shadow" in text_value:
        return "HIGH"

    if (
        ("wget " in text_value or "curl " in text_value or "http://" in text_value or "https://" in text_value)
        and "chmod +x" in text_value
        and "./" in text_value
    ):
        return "HIGH"

    if "| bash" in text_value or "| sh" in text_value:
        return "HIGH"

    if any(token in text_value for token in ["nc -e", "/bin/bash -i", "bash -i", "reverse shell"]):
        return "HIGH"

    if any(token in text_value for token in ["useradd ", "usermod ", "visudo", "/etc/sudoers", "backdoor"]):
        return "HIGH"

    if any(token in text_value for token in ["sudo su", "sudo -i", "passwd ", "chpasswd", "crontab", "systemctl ", "service "]):
        return "MEDIUM"

    if any(token in text_value for token in ["wget ", "curl ", "http://", "https://", "malware.sh", "bot.sh", "payload.sh", "miner.sh", "dropper.sh"]):
        return "MEDIUM"

    if "cat /etc/passwd" in text_value:
        return "MEDIUM"

    return "LOW"


def severity_floor_from_attack_class(attack_class: str, command_score: float, event_type: str) -> str:
    attack = (attack_class or "normal").lower()
    normalized_type = normalize_event_type(event_type)

    if attack in {"destructive_activity", "exploitation"}:
        return "HIGH"

    if attack in {"privilege_abuse", "ddos"} and command_score >= 0.55:
        return "HIGH"

    if attack in {"credential_attack", "web_attack", "reconnaissance", "privilege_abuse"}:
        return "MEDIUM"

    if normalized_type == "web" and command_score >= 0.70:
        return "HIGH"

    if command_score >= 0.88:
        return "HIGH"
    if command_score >= 0.40:
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

    app_state["hybrid_info"] = "Adaptive confidence-aware hybrid engine active: LSTM + CICIoT + rule fallback + severity floor"
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
        score = max(confidence * 0.90, 0.60)
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
    high_terms = ["malware", "payload", "exploit", "exploitation", "shell", "bruteforce", "backdoor", "attack", "privilege", "abuse"]

    if any(term in label_lower for term in benign_terms):
        return 0.05 * max(prob, 0.5)
    if any(term in label_lower for term in medium_terms):
        return 0.45 + 0.30 * prob
    if any(term in label_lower for term in high_terms):
        return 0.70 + 0.25 * prob

    return 0.25 + 0.30 * prob


def predict_lstm_from_session(session_id: str, command: str, event_type: str = "ssh") -> Dict[str, Any]:
    normalized_type = normalize_event_type(event_type)

    if normalized_type != "ssh":
        return {
            "lstm_session": "NotUsedForWeb",
            "session_length": 0,
            "lstm_score": 0.0,
            "lstm_confidence": 0.0,
        }

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


def compute_dynamic_weights(
    *,
    event_type: str,
    command_score: float,
    lstm_confidence: float,
    ciciot_confidence: float,
    has_ciciot: bool,
) -> Dict[str, float]:
    normalized_type = normalize_event_type(event_type)

    w_lstm = 0.25
    w_ciciot = 0.0
    w_command = 0.75 if not has_ciciot else 0.45

    if lstm_confidence >= LSTM_HIGH_CONFIDENCE:
        w_lstm = 0.45
    elif lstm_confidence >= LSTM_MEDIUM_CONFIDENCE:
        w_lstm = 0.30
    else:
        w_lstm = 0.20

    if has_ciciot:
        if ciciot_confidence >= CICIOT_HIGH_CONFIDENCE:
            w_ciciot = 0.35
        elif ciciot_confidence >= CICIOT_MEDIUM_CONFIDENCE:
            w_ciciot = 0.25
        else:
            w_ciciot = 0.15
    else:
        w_ciciot = 0.0

    if normalized_type == "ssh":
        if command_score >= 0.85:
            w_command = 0.50
        elif command_score >= 0.55:
            w_command = 0.40
        else:
            w_command = 0.35 if has_ciciot else 0.55
    else:
        if command_score >= 0.80:
            w_command = 0.50
        elif command_score >= 0.60:
            w_command = 0.42
        else:
            w_command = 0.35 if has_ciciot else 0.60

    total = w_lstm + w_ciciot + w_command
    if total <= 0:
        return {"lstm": 0.3, "ciciot": 0.0, "command": 0.7}

    return {
        "lstm": round(w_lstm / total, 4),
        "ciciot": round(w_ciciot / total, 4),
        "command": round(w_command / total, 4),
    }


def derive_anomaly_boost(
    *,
    event_type: str,
    command_score: float,
    lstm_confidence: float,
    ciciot_confidence: float,
    attack_class_hint: Optional[str],
) -> float:
    normalized_type = normalize_event_type(event_type)
    hint = (attack_class_hint or "normal").lower()

    max_model_conf = max(lstm_confidence, ciciot_confidence)

    if max_model_conf < 0.35 and command_score >= 0.70:
        if hint in {"exploitation", "destructive_activity", "privilege_abuse", "web_attack", "credential_attack"}:
            return 0.10
        if hint in {"reconnaissance", "ddos"}:
            return 0.06

    if normalized_type == "web" and command_score >= 0.78:
        return 0.05

    return 0.0


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
    source in {"lstm", "ciciot", "hybrid", "fallback_rule", "command"}
    """
    normalized_type = normalize_event_type(event_type)
    normalized_lstm = normalize_attack_label(lstm_session)
    normalized_ciciot = normalize_attack_label(ciciot_attack)

    if normalized_type == "ssh":
        explicit_class = get_explicit_ssh_command_class(raw_text)

        if explicit_class in {"destructive_activity", "privilege_abuse"}:
            return explicit_class, "command"

        if explicit_class == "credential_attack" and command_score >= 0.35:
            return explicit_class, "command"

        if explicit_class == "exploitation" and command_score >= 0.52 and lstm_confidence < LSTM_HIGH_CONFIDENCE:
            return explicit_class, "command"

        if explicit_class == "reconnaissance" and command_score >= 0.20 and lstm_confidence < LSTM_HIGH_CONFIDENCE:
            return explicit_class, "command"

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

    fallback = classify_web_attack_fallback(raw_text)
    if fallback != "normal":
        return fallback, "fallback_rule"

    if normalized_lstm and normalized_lstm != "normal" and lstm_confidence >= LSTM_HIGH_CONFIDENCE and threat_score >= 0.65:
        return normalized_lstm, "lstm"

    return "normal", "fallback_rule"


def fuse_hybrid_decision(
    command: str,
    session_id: str,
    event_type: str = "ssh",
    ciciot_features: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    normalized_type = normalize_event_type(event_type)

    lstm_result = predict_lstm_from_session(
        session_id=session_id,
        command=command,
        event_type=normalized_type,
    )
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

    lstm_score = float(lstm_result.get("lstm_score", 0.0))
    lstm_confidence = float(lstm_result.get("lstm_confidence", 0.0))
    ciciot_score = float(ciciot_result.get("ciciot_score", 0.0))
    ciciot_confidence = float(ciciot_result.get("ciciot_confidence", 0.0))
    has_ciciot = bool(ciciot_features)

    provisional_class = (
        classify_ssh_attack_fallback(command, lstm_session=lstm_result.get("lstm_session"))
        if normalized_type == "ssh"
        else classify_web_attack_fallback(command)
    )

    weights = compute_dynamic_weights(
        event_type=normalized_type,
        command_score=command_score,
        lstm_confidence=lstm_confidence,
        ciciot_confidence=ciciot_confidence,
        has_ciciot=has_ciciot,
    )

    raw_threat_score = (
        weights["lstm"] * lstm_score
        + weights["ciciot"] * ciciot_score
        + weights["command"] * command_score
    )

    anomaly_boost = derive_anomaly_boost(
        event_type=normalized_type,
        command_score=command_score,
        lstm_confidence=lstm_confidence,
        ciciot_confidence=ciciot_confidence,
        attack_class_hint=provisional_class,
    )

    threat_score = round(clamp01(raw_threat_score + anomaly_boost), 4)

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
    class_floor = severity_floor_from_attack_class(
        attack_class=attack_class,
        command_score=command_score,
        event_type=normalized_type,
    )
    floor_severity = max_severity(emergency_floor, class_floor)
    final_severity = max_severity(base_severity, floor_severity)
    policy_escalated = final_severity != base_severity

    if final_severity == "HIGH" and threat_score < 0.75:
        threat_score = round(max(threat_score, 0.75, command_score, lstm_score, ciciot_score), 4)
    elif final_severity == "MEDIUM" and threat_score < 0.40:
        threat_score = round(max(threat_score, 0.40, command_score * 0.8), 4)

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

    reason = infer_reason(
        event_type=normalized_type,
        raw_text=command,
        attack_class=attack_class,
        decision_source=decision_source,
        severity=final_severity,
        policy_escalated=policy_escalated,
    )

    return {
        "severity": final_severity,
        "threat_score": threat_score,
        "attack_class": attack_class,
        "reason": reason,
        "decision_source": decision_source,
        "fusion_method": "adaptive_confidence_hybrid_lstm_ciciot_command_fallback",
        "base_severity": base_severity,
        "floor_severity": floor_severity,
        "policy_escalated": policy_escalated,
        "fusion_weights": weights,
        "hybrid_weights": weights,
        "anomaly_boost": round(anomaly_boost, 4),
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
        "reason": event.reason or "benign_activity",
        "severity": normalize_severity(event.severity),
        "threat_score": round(float(event.threat_score or 0.0), 4),
        "lstm_session": event.lstm_session or "Unknown",
        "lstm_score": round(float(event.lstm_score or 0.0), 4),
        "command_score": round(float(event.command_score or 0.0), 4),
        "ciciot_attack": event.ciciot_attack,
        "ciciot_confidence": round(float(event.ciciot_confidence or 0.0), 4),
        "ciciot_score": round(float(event.ciciot_score or 0.0), 4),
        "decision_source": event.decision_source or "rules",
        "fusion_method": event.fusion_method or "adaptive_hybrid_lstm_ciciot_command",
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
        hybrid["reason"] = "policy_escalation_or_rate_limit_trigger"

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
        reason=hybrid["reason"],
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
    event_payload["fusion_weights"] = hybrid.get("fusion_weights", {})
    event_payload["anomaly_boost"] = hybrid.get("anomaly_boost", 0.0)
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
    return predict_lstm_from_session(model_session_id, payload.command, event_type="ssh")


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
