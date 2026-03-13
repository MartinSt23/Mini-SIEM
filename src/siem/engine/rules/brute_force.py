from collections import defaultdict
from datetime import datetime, timedelta

_failed = defaultdict(list)
_alerted = set()

def check(event: dict) -> dict | None:
        if event.get("event_type") != "LOGIN_FAILED":
            return None
        
        ip = event["source_ip"]
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=60)
        
        _failed[ip] = [t for t in _failed[ip] if t > cutoff]
        _failed[ip].append(now)
        
        if len(_failed[ip]) >= 5 and ip not in _alerted:
            _alerted.add(ip)
            return {
                "alert_type": "BRUTE_FORCE",
                "source_ip": ip,
                "severity": "HIGH",
                "message": f"{len(_failed[ip])} fehlgeschlagene Logins in 60s",
            }