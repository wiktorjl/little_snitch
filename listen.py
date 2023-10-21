import scapy.all as scapy
import socket
import subprocess
import re
import os
import sys

def get_os():
    if os.name == 'nt':
        return 'Windows'
    elif os.name == 'posix':
        if sys.platform.startswith('linux'):
            return 'Linux'
        elif sys.platform == 'darwin':
            return 'macOS'
        else:
            return 'POSIX-like OS'
    else:
        return 'Unknown OS'


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

def get_program_name(port):
    try:
        # Fetch processes associated with network activity
        command_output = subprocess.check_output(["netstat", "-ano", "-p", "TCP"]).decode('utf-8')
        for line in command_output.splitlines():
            # Find lines with established connections and the specified port
            if "ESTABLISHED" in line and f":{port}" in line:
                pid = line.strip().split()[-1]
                # Get process name by PID
                tasks = subprocess.check_output(["tasklist", "/FI", f"PID eq {pid}"]).decode('utf-8')
                match = re.search(r'(.+?)\s+\d+\s+', tasks)
                if match:
                    return match.group(1)
    except Exception as e:
        pass
    return "Unknown"

def packet_callback(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        dst_port = packet[scapy.TCP].dport
        if dst_ip == scapy.get_if_addr(scapy.conf.iface) and src_ip not in seen_ips:
            hostname = get_hostname(src_ip)
            program_name = get_program_name(dst_port)
            print(f"Incoming connection from {src_ip} ({hostname}) to program: {program_name}")
            seen_ips.add(src_ip)

if get_os() == 'Windows':
    seen_ips = set()
    scapy.sniff(prn=packet_callback, store=0, filter="ip")
else:
    print("Only Windows supported for now...")