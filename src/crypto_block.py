import re
from scapy.all import *
from subprocess import run
from numpy import mean
from psutil import cpu_percent, virtual_memory
from collections import *
from time import sleep, time


def time_out(seconds):
    return round(time() + seconds)

def isCpuSpike(duration, cpu_usage, percent_limit):
    limit_time = time_out(duration)
    while(limit_time > time()):
        # cpu_usage = mean(cpu_percent(interval=1, percpu=True))
        if(cpu_usage >= percent_limit): 
            print("CPU spike detected")
            return True

    return False

def block():
    detected_ips = []
    
    while(True):
        pkg_list = sniff(timeout=1, filter="tcp")
        stratum_tag = ['jsonrpc']
        r = re.compile(r'\bjsonrpc\b | \bjob\b | \bblob\b', flags=re.I | re.X)

        for pkg in pkg_list:
            if(pkg[1].haslayer(Raw)): 
                #Convert bytes payload to str
                payload_str = linehexdump(pkg.load, onlyasc=1, dump=True) 
                pattern = all(tags in r.findall(payload_str) for tags in stratum_tag)
                # print(payloadStr)

                if(pattern):
                    if(pkg[1].dst not in detected_ips):
                        store_miner_ip(pkg[1].dst)
                        detected_ips.append(pkg[1].dst)
                        send_alert_to_firewall(pkg[1].dst)
            else:
                continue
            
def send_alert_to_firewall(ip):
    print("Blocking address", ip)
    run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])  

def store_miner_ip(_ip):
    file = open("src/blacklisted_ips.txt", "a")
    file.write(str(_ip) + "\n")
    file.close

def start():
    block()