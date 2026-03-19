from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from typing import Optional

Base = declarative_base()

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), index=True)  # IPv6 ready
    event_type = Column(String(50), index=True)  # web_login, ssh_command
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    protocol = Column(String(10), default="unknown")  # http, ssh
    username = Column(String(100), default="unknown")
    password = Column(Text, nullable=True)
    user_agent = Column(Text, nullable=True)
    command = Column(Text, nullable=True)
    session_id = Column(String(100), default="session")
    severity = Column(String(20), default="low")
    country = Column(String(100), nullable=True)  # ✅ NEW: GeoIP country
