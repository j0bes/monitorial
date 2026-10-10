# IMPORTS
from threading import Thread
from flask import Flask, render_template

from database.db import init_db
from database.scans import get_scan_progress, create_scan, load_scan

from scanner.scan_service import run_scan
from scanner.network import get_network, get_hosts

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
    items = get_scan_progress(scan_id)
    try:
        percentage = (items[1]/items[0])*100
    except ZeroDivisionError:
        print("No ip scanned for the moment.")
    return {"percentage": percentage}

@app.route("/api/scan/<scan_id>/hosts", methods=['GET'])
def scan_hosts(scan_id):
    hosts = load_scan(scan_id)
    return hosts

if __name__ == "__main__":

    init_db()
    app.run(debug=True, threaded=True)