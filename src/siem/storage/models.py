from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime

class Base(DeclarativeBase):
    pass

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    source_ip = Column(String(45))
    event_type = Column(String(50))
    method = Column(String(10))
    path = Column(String(500))
    status = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    
class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    alert_type = Column(String(50))
    source_ip = Column(String(45))
    severity = Column(String(10))
    message = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)