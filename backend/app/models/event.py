from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    source_ip = Column(String, index=True)
    username = Column(String)
    password = Column(String)
    event_type = Column(String)
    command = Column(Text)
    timestamp = Column(DateTime)
    # Phase 7 columns
    attack_class = Column(Text, default="normal")
    severity = Column(String, default="LOW")
