#!/usr/bin/env python
import threading
from queue import Queue
import time
import socket
import ipaddress
import nmap

# Initialize the Nmap scanner
nm = nmap.PortScanner()

# Get the local IP address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('192.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# Get the subnet based on the local IP
def get_subnet(local_ip):
    net = ipaddress.ip_network(local_ip + '/24', strict=False)
    return net

# Scan the subnet for live hosts
def scan_subnet(ip_range):
    print(f"Scanning subnet {ip_range} for live hosts...")
    nm.scan(hosts=ip_range, arguments='-sP')
    hosts_list = [(x) for x in nm.all_hosts() if nm[x].state() == 'up']
    return hosts_list

# Scan a specific host for open ports
def scan_ports(host, ports):
    nm.scan(hosts=host, arguments=f'-p {",".join(map(str, ports))} --open')
    open_ports = []
    for port in ports:
        if nm[host].has_tcp(port):
            state = nm[host]['tcp'][port]['state']
            if state == 'open':
                open_ports.append(port)
    return open_ports

# Thread worker function to scan ports
def threader():
    while True:
        host, port = q.get()
        if is_open(host, port):
            with print_lock:
                print(f'Port {port} is open on {host}')
        q.task_done()

# Check if a port is open
def is_open(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = s.connect_ex((host, port))
    s.close()
    return result == 0

# Main function
if __name__ == "__main__":
    # Initialize variables and threads
    print_lock = threading.Lock()
    q = Queue()

    for x in range(100):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    # Get local IP and subnet
    local_ip = get_local_ip()
    subnet = get_subnet(local_ip)
    print(f"Local IP: {local_ip}")
    print(f"Subnet: {subnet}")

    # Scan for live hosts
    live_hosts = scan_subnet(str(subnet))
    print(f"Live hosts on subnet: {live_hosts}")

    # Define ports to scan
    ports = [22, 3389, 53, 80, 443, 21, 8080, 8081]

    # Start time
    start = time.time()

    # Enqueue port scans for live hosts
    for host in live_hosts:
        for port in ports:
            q.put((host, port))

    q.join()

    # End time
    end = time.time()
    print(f"Scanning completed in {end - start:.2f} seconds.")
