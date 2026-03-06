import re
from .base import BaseParser

PATTERN= re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

class ApacheParser(BaseParser):
    def parse(self, raw: str) -> dict | None:
            m = PATTERN.match(raw)
            if not m:
                return None
            return {
                "source_ip": m.group("ip"),
                "timestamp": m.group("time"),
                "method": m.group("method"),
                "path": m.group("path"),
                "status": int(m.group("status")),
                "size": m.group("size"),
                "event_type": self._classify(int(m.group("status"))),
            }

    def _classify(self, status: int) -> str:
        if status == 401: return "LOGIN_FAILED"
        if status >= 500: return "SERVER_ERROR"
        if status >= 400: return "CLIENT_ERROR"
        return "SUCCESS"