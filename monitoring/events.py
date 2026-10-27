# IMPORTS
from database.scans import load_scan

def detect_new_hosts(current_scan, previous_scan):
    current_hosts = current_scan["hosts"]
    previous_hosts = previous_scan["hosts"]
    timestamp = current_scan["timestamp"]
    new_hosts = []

    for ip, host in current_hosts.items():
        if ip not in previous_hosts:
            new_hosts.append({
                "type": "NEW_HOST",
                "ip": ip,
                "timestamp": timestamp,
                "data": {
                    "hostname": host["hostname"],
                    "port": None,
                    "service": None,
                    "product": None,
                    "version": None
                }
            })

    return new_hosts

def detect_removed_hosts(current_scan, previous_scan):
    current_hosts = current_scan["hosts"]
    previous_hosts = previous_scan["hosts"]
    timestamp = current_scan["timestamp"]
    removed_hosts = []

    for ip, host in previous_hosts.items():
        if ip not in current_hosts:
            removed_hosts.append({
                "type": "REMOVED_HOST",
                "ip": ip,
                "timestamp": timestamp,
                "data": {
                    "hostname": host["hostname"],
                    "port": None,
                    "service": None,
                    "product": None,
                    "version": None
                }
            })

    return removed_hosts

def detect_new_ports(current_scan, previous_scan):
    current_hosts = current_scan["hosts"]
    previous_hosts = previous_scan["hosts"]
    timestamp = current_scan["timestamp"]
    new_ports = []

    for ip, host in current_hosts.items():
        if ip in previous_hosts:

            for port, port_data in host["ports"].items():
                if port not in previous_hosts[ip]["ports"]:
                    new_ports.append({
                        "type": "NEW_PORT",
                        "ip": ip,
                        "timestamp": timestamp,
                        "data": {
                            "hostname": host["hostname"],
                            "port": port,
                            "service": port_data["service"],
                            "product": port_data["product"],
                            "version": port_data["version"]
                        }
                    })

    return new_ports

def detect_closed_ports(current_scan, previous_scan):
    current_hosts = current_scan["hosts"]
    previous_hosts = previous_scan["hosts"]
    timestamp = current_scan["timestamp"]
    closed_ports = []

    for ip, host in previous_hosts.items():
        if ip in current_hosts:

            for port, port_data in host["ports"].items():
                if port not in current_hosts[ip]["ports"]:
                    closed_ports.append({
                        "type": "CLOSED_PORT",
                        "ip": ip,
                        "timestamp": timestamp,
                        "data": {
                            "hostname": host["hostname"],
                            "port": port,
                            "service": port_data["service"],
                            "product": port_data["product"],
                            "version": port_data["version"]
                        }
                    })

    return closed_ports

def detect_service_changes(current_scan, previous_scan):
    current_hosts = current_scan["hosts"]
    previous_hosts = previous_scan["hosts"]
    timestamp = current_scan["timestamp"]
    service_changes = []

    for ip, host in current_hosts.items():
        if ip in previous_hosts:

            for port, port_data in host["ports"].items():
                if port in previous_hosts[ip]["ports"]:
                    previous_port = previous_hosts[ip]["ports"][port]

                    # detection failed on one of the scans: not a real change
                    if port_data["service"] is None or previous_port["service"] is None:
                        continue

                    if port_data["service"] != previous_hosts[ip]["ports"][port]["service"]:
                        service_changes.append({
                            "type": "SERVICE_CHANGED",
                            "ip": ip,
                            "timestamp": timestamp,
                            "data": {
                                "hostname": host["hostname"],
                                "port": port,
                                "previous": {
                                    "service": previous_hosts[ip]["ports"][port]["service"],
                                    "product": previous_hosts[ip]["ports"][port]["product"],
                                    "version": previous_hosts[ip]["ports"][port]["version"]
                                },
                                "current": {
                                    "service": port_data["service"],
                                    "product": port_data["product"],
                                    "version": port_data["version"]
                                }
                            }
                        })

    return service_changes

def detect_version_changes(current_scan, previous_scan):
    current_hosts = current_scan["hosts"]
    previous_hosts = previous_scan["hosts"]
    timestamp = current_scan["timestamp"]
    version_changes = []

    for ip, host in current_hosts.items():
        if ip in previous_hosts:

            for port, port_data in host["ports"].items():
                if port in previous_hosts[ip]["ports"]:
                    previous_port = previous_hosts[ip]["ports"][port]

                    # detection failed on one of the scans: not a real change
                    if port_data["service"] is None or previous_port["service"] is None:
                        continue
                    
                    if port_data["version"] != previous_hosts[ip]["ports"][port]["version"] and port_data["service"] == previous_hosts[ip]["ports"][port]["service"]:
                        version_changes.append({
                            "type": "VERSION_CHANGED",
                            "ip": ip,
                            "timestamp": timestamp,
                            "data": {
                                "hostname": host["hostname"],
                                "port": port,
                                "previous": {
                                    "service": previous_hosts[ip]["ports"][port]["service"],
                                    "product": previous_hosts[ip]["ports"][port]["product"],
                                    "version": previous_hosts[ip]["ports"][port]["version"]
                                },
                                "current": {
                                    "service": port_data["service"],
                                    "product": port_data["product"],
                                    "version": port_data["version"]
                                }
                            }
                        })

    return version_changes

# Functions that generate the events dict
EVENT_DETECTOR = [
    detect_new_hosts,
    detect_removed_hosts,
    detect_new_ports,
    detect_closed_ports,
    detect_service_changes,
    detect_version_changes
]

def generate_events(scan_id, previous_scan_id):
    events = []

    current_scan = load_scan(scan_id)
    previous_scan = load_scan(previous_scan_id)

    for detector in EVENT_DETECTOR:
        events.extend(detector(current_scan, previous_scan))

    return events