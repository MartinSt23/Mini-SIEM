from siem.engine.rules import brute_force

RULES = [
    brute_force.check,
]

def evaluate(event: dict) -> dict | None:
    for rule in RULES :
        result = rule(event)
        if result:
            return result
    return None