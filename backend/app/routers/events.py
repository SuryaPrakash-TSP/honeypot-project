from fastapi import APIRouter, HTTPException
from pathlib import Path
import json
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["honeypot"])  # Remove prefix="/api"

COWRIE_LOG_PATH = Path("./cowrie.json")

@router.get("/ssh_attacks")
async def get_ssh_attacks(limit: int = 50) -> Dict[str, Any]:
    """
    Fetch recent SSH honeypot attacks from Cowrie JSON logs.
    Returns formatted events with masked passwords.
    """
    if not COWRIE_LOG_PATH.exists():
        logger.warning("Cowrie log not found")
        raise HTTPException(status_code=404, detail="Cowrie log file not found")

    try:
        with open(COWRIE_LOG_PATH, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        ssh_events: List[Dict[str, Any]] = []
        for line in lines[-limit*2:]:  # Buffer for non-SSH lines
            try:
                event = json.loads(line.strip())
                if event.get("protocol") == "ssh":
                    ssh_events.append({
                        "timestamp": event.get("timestamp"),
                        "src_ip": event.get("src_ip"),
                        "eventid": event.get("eventid"),
                        "username": event.get("username", ""),
                        "password": (event.get("password", "")[:4] + "***") if event.get("password") else "",
                        "input_cmd": event.get("input", ""),
                        "session": event.get("session", ""),
                        "duration": event.get("duration", "")
                    })
                    if len(ssh_events) >= limit:
                        break
            except json.JSONDecodeError:
                continue

        logger.info(f"Retrieved {len(ssh_events)} SSH events")
        return {"ssh_attacks": ssh_events[::-1], "count": len(ssh_events)}  # Newest first

    except Exception as e:
        logger.error(f"SSH log read error: {e}")
        raise HTTPException(status_code=500, detail="Failed to read SSH logs")
