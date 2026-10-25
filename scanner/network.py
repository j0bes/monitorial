import netifaces
import subprocess
import platform
import socket
import os
from ipaddress import IPv4Network

def get_network():
    # manual override, e.g. SCAN_NETWORK=192.168.56.0/24 for the host-only lab
    override = os.environ.get("SCAN_NETWORK")
    if override:
        return IPv4Network(override, strict=False)

    # prefer the interface used by the default route (the "real" network)
    try:
        default_interface = netifaces.gateways()["default"][netifaces.AF_INET][1]
        interfaces = [default_interface]
    except (KeyError, IndexError):
        interfaces = netifaces.interfaces()

    for interface in interfaces:
        addrs = netifaces.ifaddresses(interface)

        # AF_INET refer to IPv4 only
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                # return for ex: {'addr': '192.168.1.50', 'netmask': '255.255.255.0', 'broadcast': '192.168.1.255'}
                ip = addr.get("addr")
                netmask = addr.get("netmask")
                # skip loopback and link-local (169.254.x.x) addresses
                if ip and netmask and not ip.startswith(("127.", "169.254.")):
                    return IPv4Network(f"{ip}/{netmask}", strict=False) # CIDR notation

def get_hosts(network: str):
    ips = list(network.hosts())
    return ips # return a list of every ip on the network (/24 would have 254 ip)

def ping_ip(ip: str):
    os_name = platform.system() # detect OS as "Windows", "Linux", "Darwin" (MacOS)

    if os_name == "Windows":
        command = ["ping", "-n", "1", "-w", "300", ip] # -n number of packet, -w for the waiting time 0.3s
    else:
        command = ["ping", "-c", "1", "-w", "3", ip]

    try:
        res = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        ) # run the ping command 
        return res.returncode == 0 # True
    except Exception as e:
        print(e)
        return False

def get_hostname(ip: str):
    hostname = socket.getfqdn(ip) 
    if hostname == ip:
        return None
    return hostname