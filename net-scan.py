# needed packages
#  pip install python-nmap (as sudo for OS fingerprinting)
# nmap is needed as well. On macOS: brew install nmap

#!/usr/bin/env python
import threading,os
from queue import Queue
import time
import socket
import ipaddress
import nmap

nm = nmap.PortScanner()

# get local IP wherever the script runs
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('192.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# get the subnet the device running the script is on
def getSubnet(local_ip):
    net = ipaddress.ip_network(local_ip+'/255.255.255.0', strict=False)
    return net

# scan ports by running a nmap scan
def scan(IPRange):
    nm.scan(hosts=IPRange, arguments='-sP -PS22,3389')
    #for x in nm.all_hosts():
        #print(nm[x])
    #hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    hosts_list = [(x) for x in nm.all_hosts()]
    return hosts_list

print_lock = threading.Lock()

def isOpen(hostname, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(0.1)
    result = sock.connect_ex((hostname, port))
    sock.close()
    return result == 0

# check for live hosts
def ipScan(targets):
    livehosts = []
    for target in targets:
        #print("testing:",target)
        res = isOpen(target, 135)
        if res:
            print("live:",target)
            livehosts.append(target)
        #else:
        #    print("offline:"+target)
    return livehosts

# scan a specific port
def portscan(target,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        con = s.connect((target,port))
        with print_lock:
            print('open: [',target,':',port,']')
        con.close()
    except:
        #con.close()
        pass

# The threader thread pulls an worker from the queue and processes it
def threader():
    while True:
        # gets an worker from the queue
        worker = q.get()
        portscan(worker[0],worker[1])
        q.task_done()

# Create the queue and threader 
q = Queue()

# how many threads are we going to allow for
for x in range(100):
     t = threading.Thread(target=threader)

     # classifying as a daemon, so they will die when the main dies
     t.daemon = True

     # begins, must come after daemon definition
     t.start()



local_ip = get_local_ip()
subnet = getSubnet(local_ip)

print("subnet:"+str(subnet))

# get the list of live hosts on a subnet
hosts_list = scan(str(subnet)) #'192.168.207.1/24'

print("live hosts on subnet:"+str(hosts_list))

# scan ports 1 to 10000
ports = range(1,10000)
ports = [22,3389,53,80,443,21,8080,8081]

start = time.time()
for target in hosts_list:
    for port in ports:
        q.put([target,port])

# wait until the thread terminates.
