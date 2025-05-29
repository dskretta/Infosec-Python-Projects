#Name: Landscan.py
#Author: DSkretta
#License: MIT
#Github: https://github.com/dskretta/Infosec-Python-Projects/blob/main/Project5.Landscan.py
#Description: This script will be used for living off the land network mapping

import subprocess
import socket
import ipaddress
import argparse

# Ping a single host
def is_host_up(ip, test_ports=[80, 443, 22, 53, 139, 445]):
    for port in test_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    return True
        except Exception:
            continue
    return False
    
# Scan selected ports on a host
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            continue
    return open_ports

# Get list of top ports to scan (these can be replaced with real Nmap data)
def get_top_ports(n):
    common_ports = [
        22, 80, 443, 21, 23, 25, 3389, 110, 445, 139,
        53, 3306, 8080, 5900, 1433, 111, 995, 1723, 993, 1025
    ]
    return common_ports[:n]

def main():
    parser = argparse.ArgumentParser(description="Project 5: Living off the Land Scanner")
    parser.add_argument("--network", required=True, help="CIDR network block to scan (e.g. 192.168.1.0/24)")
    parser.add_argument("--top", type=int, choices=[10, 100, 1000], default=10, help="Scan top x ports (10/100/1000)")

    args = parser.parse_args()
    net = ipaddress.ip_network(args.network, strict=False)
    ports = get_top_ports(args.top)

    live_hosts = []

    print(f"[*] Scanning network {args.network} for live hosts...")
    for host in net.hosts():
        if is_host_up(host):
            print(f"[+] Host is up: {host}")
            live_hosts.append(host)

    for host in live_hosts:
        print(f"\n[*] Scanning ports on {host}")
        open_ports = scan_ports(host, ports)
        for port in open_ports:
            print(f"  [OPEN] {host}:{port}")

if __name__ == "__main__":
    main()
