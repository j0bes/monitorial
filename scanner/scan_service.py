# IMPORTS
from database.scans import update_scan_status, increment_scan_progress
from database.hosts import save_host
from database.ports import save_port

from scanner.network import ping_ip, get_hostname
from scanner.ports import scan_ports, detect_services

from concurrent.futures import ThreadPoolExecutor, as_completed
from getmac import get_mac_address as gma
from time import perf_counter

from monitoring.events import generate_events

def run_scan(scan_id: int, ips: list):

    t=perf_counter()

    # Threadpool allows us to execute code simultaneously
    try:
        with ThreadPoolExecutor(max_workers=50) as exec:
            tasks = [ exec.submit(scan_ip, ip) for ip in ips ]

            # for the completed task we can continue 
            for task in as_completed(tasks):
                try:
                    results = task.result()
                        
                    if results["active"]:
                        host_id = save_host(
                            scan_id,
                            results["ip"],
                            results["hostname"],
                            results["mac"]
                        )

                        for port, service_info in results["ports_services"].items():
                            save_port(
                                host_id,
                                port,
                                service_info["protocol"],
                                service_info["service"],
                                service_info["product"],
                                service_info["version"]
                            )
                except Exception as e:
                    print(f"error in the scan: {e}")

                # When one ip is scanned, +1 on the progress
                finally:
                    increment_scan_progress(scan_id)

        # When the scan is finish, update the status value on scans table
        update_scan_status(scan_id, "completed")

    # if an error occurred during the scan, update status has: "failed"
    except Exception as e:
        update_scan_status(scan_id, "failed")
        print(f"scan {scan_id} failed.")

    print(f"TOTAL: {perf_counter()-t:.2f}s")

def scan_ip(ip):
    t=perf_counter()
    ip = str(ip)
    if not ping_ip(ip):
        return {
            "ip": ip,
            "active": False,
            "hostname": '',
            "mac": '',
            "ports_services": {}
        }

    hostname = get_hostname(ip)
    mac = gma(ip=ip)
    open_ports = scan_ports(ip)
    services = detect_services(ip, open_ports) # contain: port, protocol, service, product, version

    print(f"{ip}: {perf_counter()-t:.2f}s")
    return {
        "ip": ip,
        "active": True,
        "hostname": hostname,
        "mac": mac,
        "ports_services": services 
    }