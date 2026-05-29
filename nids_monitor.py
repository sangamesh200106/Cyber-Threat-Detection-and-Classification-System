import re
import time

suspicious_patterns = ["malicious", "exploit", "attack", "<script>"]

def check_payload(payload):
    """
    Checks if payload contains suspicious patterns.
    Returns dict with severity and matched info.
    """
    matched = []
    decoded = payload.decode(errors='ignore') if isinstance(payload, bytes) else str(payload)

    for pattern in suspicious_patterns:
        if re.search(re.escape(pattern), decoded, re.IGNORECASE):
            matched.append(pattern)

    if matched:
        return {
            "severity": "HIGH",
            "patterns": matched,
            "payload": decoded,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    else:
        return {
            "severity": "NORMAL",
            "patterns": [],
            "payload": decoded,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
