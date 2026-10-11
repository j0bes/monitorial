from database.db import get_connection

def save_port(host_id: int, port: int, protocol:str, service: str, product: str, version: str):
    con = get_connection()
    con.execute(
        "INSERT INTO ports (host_id, port, protocol, service, product, version) VALUES (?,?,?,?,?,?)", (host_id, port, protocol, service, product, version)
    )
    con.commit()
    con.close()