import socket
import subprocess
import xml.etree.ElementTree as ET

# to limited the time of the scan, I only added common ports
lst_ports = [
    21, 22, 23, 25, 53,   
    80, 110, 139, 143,
    443, 445, 3389,
    8080
]

def scan_ports(ip: str):
    open_ports = []

    for port in lst_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.6)
            res = sock.connect_ex((ip, port))

            if res == 0:
                open_ports.append(port)

        except socket.error as e:
            print(e)
    return open_ports

def detect_services(ip: str, open_ports: list):
    ports_services = {}

    for port in open_ports:
        ports_services[port] = {
            "protocol": "tcp",
            "service": None,
            "product": None,
            "version": None
        }

    if not open_ports:
        return ports_services

    ports = ",".join(str(port) for port in open_ports)

    try:
        result = subprocess.run(
            [   
                "nmap",
                "-sV",
                "-p", ports,
                "-oX", "-",
                ip
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print(f"Nmap error: {result.stderr}")
            return ports_services

        root = ET.fromstring(result.stdout)

        for port in root.findall(".//port"):
            port_id = int(port.get("portid"))
            protocol = port.get("protocol")

            service = port.find("service")

            if service:
                service_name = service.get("name", "")
                product = service.get("product", "")
                version = service.get("version", "")
    
                ports_services[port_id] = {
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version
                }

    except subprocess.TimeoutExpired:
        print(f"Nmap timeout pour {ip}")

    except subprocess.SubprocessError as e:
        print(f"Erreur Nmap : {e}")

    except ET.ParseError as e:
        print(f"Erreur parsing Nmap : {e}")

    return ports_services