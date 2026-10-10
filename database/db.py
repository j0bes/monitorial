import sqlite3

DB_PATH = "network.db"

# Function that initialise a connection to the db
def get_connection():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute(
        "PRAGMA  foreign_keys = ON;"
    )
    return con

# Function that create table if they don't exist
def init_db():
    con = get_connection()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL,
            total_ips INT NOT NULL,
            completed_ips INT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hosts(
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT,
            mac TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS ports(
            id INTEGER PRIMARY KEY,
            host_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        );

        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY,
            previous_scan_id INTEGER,
            current_scan_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (previous_scan_id) REFERENCES scans(id),
            FOREIGN KEY (current_scan_id) REFERENCES scans(id)
        );
    """)
    con.commit()
    con.close()
