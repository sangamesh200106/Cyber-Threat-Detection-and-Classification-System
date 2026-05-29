from scapy.all import rdpcap, Raw
import logging
import re

# Log file in project directory
logging.basicConfig(filename='nids_alerts.log', level=logging.INFO, format='%(asctime)s - %(message)s')

suspicious_patterns = ["malicious", "exploit", "attack", "<script>"]  # add any patterns here

def automata_match(payload):
    decoded = payload.decode(errors='ignore')
    matched = []
    for pattern in suspicious_patterns:
        if re.search(re.escape(pattern), decoded, re.IGNORECASE):
            matched.append(pattern)
    return matched

def highlight_payload(payload, patterns):
    decoded = payload.decode(errors='ignore')
    for p in patterns:
        decoded = re.sub(re.escape(p), f'<span style="color:red;font-weight:bold;">{p}</span>', decoded, flags=re.IGNORECASE)
    return decoded

def risk_assessment(patterns):
    if any(p.lower() in ["malicious", "attack", "<script>"] for p in patterns):
        return "HIGH"
    return "MEDIUM"

def analyze_pcap(file):
    packets = rdpcap(file)
    alerts = []
    for packet in packets:
        if Raw in packet:
            payload = packet[Raw].load
            matched_patterns = automata_match(payload)
            if matched_patterns:
                highlighted = highlight_payload(payload, matched_patterns)
                severity = risk_assessment(matched_patterns)
                alert = f"[{severity} ALERT] Pattern(s) {', '.join(matched_patterns)} detected in payload: {highlighted}"
                print(alert)
                logging.info(alert)
                alerts.append(alert)
    # flush handlers
    for h in logging.getLogger().handlers:
        try:
            h.flush()
        except Exception:
            pass
    return alerts

if __name__ == "__main__":
    analyze_pcap('traffic_capture.pcap')
