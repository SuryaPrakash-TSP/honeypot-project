from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Event(Base):
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), index=True)  # IPv6 ready
    event_type = Column(String(50), index=True)  # web_login, ssh_command
    timestamp = Column(DateTime, default=datetime.utcnow)
    protocol = Column(String(10))  # http, ssh
    username = Column(String(100))
    password = Column(Text)
    user_agent = Column(Text)
    command = Column(Text)
    session_id = Column(String(100))
    severity = Column(String(20), default="low")
