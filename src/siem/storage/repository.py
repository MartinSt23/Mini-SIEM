from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, Event, Alert

class Repository:
    def __init__(self, db_url: str = "sqlite:///siem.db"):
        engine = create_engine(db_url)
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)
        
    def save_event(self, data: dict):
        with self.Session() as s:
            s.add(Event(
                source_ip = data.get("source_ip"),
                event_type = data.get("event_type"),
                method = data.get("method"),
                path = data.get("path"),
                status = data.get("status"),
            ))
            s.commit()
    
    def save_alert(self, data: dict):
        with self.Session() as s:
            s.add(Alert(
                alert_type = data.get("alert_type"),
                source_ip = data.get("source_ip"),
                severity = data.get("severity"),
                message = data.get("message"),
            ))
            s.commit()
            
    def get_recent_alerts(self, limit: int = 100) -> list:
        with self.Session() as s:
            return s.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()