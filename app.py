from flask import Flask, render_template, request, jsonify
import nids_monitor
import logging
import os
import time

app = Flask(__name__)

# setup logging
logging.basicConfig(filename="nids_alerts.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s")

alerts = []  # store alerts in memory
nids_active = True  # toggle with ON/OFF button

@app.route('/')
def index():
    return render_template("index.html", nids_active=nids_active)

@app.before_request
def inspect_request():
    global alerts, nids_active
    if not nids_active:
        return None  # if NIDS off, do nothing

    client_ip = request.remote_addr
    payload = request.query_string.decode()  # capture GET parameters

    result = nids_monitor.check_payload(payload)
    alert_entry = {
        "ip": client_ip,
        "time": result["timestamp"],
        "payload": result["payload"],
        "severity": result["severity"],
        "patterns": result["patterns"]
    }

    alerts.append(alert_entry)
    logging.info(str(alert_entry))

    # If high severity → stop request and trigger confirm box
    if result["severity"] == "HIGH":
        return jsonify({"alert": "HIGH", "details": alert_entry})

    return None  # allow request to continue

@app.route('/get_alerts')
def get_alerts():
    global alerts
    return jsonify(alerts[-50:])  # last 50 alerts

@app.route('/clear_alerts')
def clear_alerts():
    global alerts
    alerts = []
    open("nids_alerts.log", "w").close()
    return jsonify({"status": "cleared"})

@app.route('/nids_on')
def nids_on():
    global nids_active
    nids_active = True
    return jsonify({"status": "NIDS ON"})

@app.route('/nids_off')
def nids_off():
    global nids_active
    nids_active = False
    return jsonify({"status": "NIDS OFF"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
