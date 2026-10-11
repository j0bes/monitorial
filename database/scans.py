from database.db import get_connection
from datetime import datetime, timezone

def create_scan(total_ips: int):
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    con = get_connection()
    row = con.execute(
        "INSERT INTO scans (timestamp, status, total_ips, completed_ips) VALUES (?,?,?,?)", (timestamp, "running", total_ips, 0)
    )
    scan_id = row.lastrowid
    con.commit()
    con.close()

    return scan_id

def get_last_scan_id():
    con = get_connection()

    row = con.execute(
        """
        SELECT id
        FROM scans
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    con.close()

    if row is None:
        return None

    return row["id"]

def get_scan_progress(scan_id: int):
    con = get_connection()
    row = con.execute(
        "SELECT total_ips, completed_ips, status FROM scans WHERE id = ?", (scan_id, )
    ).fetchone()
    con.close()
    return [int(row[0]), int(row[1]), row[2]]

def increment_scan_progress(scan_id: int):
    con = get_connection()
    try:
        con.execute(
            "UPDATE scans SET completed_ips = completed_ips + 1 WHERE id = ?", (scan_id, )
        )
        con.commit()
    finally:
        con.close()

def update_scan_status(scan_id: int, status: str):
    con = get_connection()
    try:
        con.execute(
            "UPDATE scans SET status = ? WHERE id = ?", (status, scan_id)
        )
        con.commit()
    finally:
        con.close()

def load_scan(scan_id):
    con = get_connection()
    hosts = {}

    # grab timestamp from scans table
    row = con.execute(
        "SELECT timestamp FROM scans WHERE id=?", (scan_id,)
    ).fetchone()
    timestamp = row[0]

    # grab hosts from hosts table
    rows = con.execute(
        "SELECT id, ip, hostname, mac FROM hosts WHERE scan_id=?", (scan_id,)
    ).fetchall()
    for row in rows:
        hosts[row["ip"]] = {
            "hostname": row["hostname"],
            "mac": row["mac"],
            "ports": {}
        }
        # grab ports from ports table
        rows_ports = con.execute(
                "SELECT * FROM ports WHERE host_id=?", (row["id"],)
            ).fetchall()
        for port in rows_ports:
            hosts[row["ip"]]["ports"][int(port["port"])] = {
                "protocol": port["protocol"],
                "service": port["service"],
                "product": port["product"],
                "version": port["version"]
            }
            
    return {
        "id": scan_id,
        "timestamp": timestamp,
        "hosts": hosts
    }

def list_scans(limit=50):
    conn = get_connection()  # ta fonction de connexion existante
    rows = conn.execute(
        "SELECT id, timestamp FROM scans WHERE status = 'completed' ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [{"id": r[0], "timestamp": r[1]} for r in rows]