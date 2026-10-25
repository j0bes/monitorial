# IMPORTS
from threading import Thread
from flask import Flask, render_template, jsonify

from database.db import init_db
from database.scans import get_scan_progress, create_scan, load_scan, list_scans, get_previous_scan_id

from scanner.scan_service import run_scan
from scanner.network import get_network, get_hosts

from monitoring.events import generate_events

app = Flask(__name__)

#Routes
@app.route("/")
def home():
    return render_template("index.html")

# Main route of the scan / start the scan
@app.route("/api/scan", methods=['POST'])
def scan():
    network = get_network()
    ips = get_hosts(network)
    scan_id = create_scan(len(ips))

    thread = Thread(target=run_scan, args=(scan_id, ips))
    thread.start()

    return {
        "success": True,
        "scan_id": scan_id,
        "status": "started"
    }

# Returns the percentage of the scan
@app.route("/api/scan/<scan_id>/progress", methods=["GET"])
def scan_progress(scan_id):
    total, scanned, status = get_scan_progress(scan_id)
    percentage = (scanned / total) * 100 if total else 0
    return {
        "percentage": percentage,
        "status": status,
        "done": status == "completed"
    }

@app.route("/api/scan/<scan_id>/hosts", methods=['GET'])
def scan_hosts(scan_id):
    hosts = load_scan(scan_id)
    return hosts

# Returns the list of scans, most recent first
@app.route("/api/scans", methods=["GET"])
def scans():
    return jsonify(list_scans())

# Returns the events of a scan compared to the previous completed scan
@app.route("/api/scan/<int:scan_id>/events", methods=["GET"])
def scan_events(scan_id):
    previous_scan_id = get_previous_scan_id(scan_id)

    # first scan: nothing to compare with
    if previous_scan_id is None:
        return {"scan_id": scan_id, "previous_scan_id": None, "events": []}

    events = generate_events(scan_id, previous_scan_id)
    return {"scan_id": scan_id, "previous_scan_id": previous_scan_id, "events": events}

if __name__ == "__main__":

    init_db()
    app.run(debug=True, threaded=True)