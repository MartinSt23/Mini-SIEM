import re

PATTERN= re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

def parse(raw: str) -> dict | None:
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
        }