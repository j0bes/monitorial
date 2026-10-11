from database.db import get_connection

def save_host(scan_id: int, ip: str, hostname: str, mac: str):
    con = get_connection()
    row = con.execute(
        "INSERT INTO hosts (scan_id, ip, hostname, mac) VALUES (?,?,?,?)", (scan_id, ip, hostname, mac)
    )
    host_id = row.lastrowid
    con.commit()
    con.close()

    return host_id
