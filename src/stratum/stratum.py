import re
from scapy.all import *
from subprocess import run
from numpy import mean
from psutil import cpu_percent, virtual_memory
from collections import *
from time import sleep, time


def time_out(seconds):
    return time() + seconds

def cpu_spike(duration, percent_limit):
    time_limit = time_out(duration)
    while(time() < time_limit):
        cpu_usage = mean(cpu_percent(percpu=True))

        if(cpu_usage >= percent_limit and virtual_memory().percent > 70.00): 
            print("CPU and Memory spikes detected")
        sleep(3)

def find_stratum(filename):
    detected_ips = []
    pkgList = rdpcap(filename)
    stratumTag = ['jsonrpc']
    r = re.compile(r'\bjsonrpc\b | \bmethod\b | \bnonce\b', flags=re.I | re.X)

    for pkg in pkgList:
        if(pkg[1].haslayer(Raw)): 
            #Convert bytes payload to str
            payloadStr = linehexdump(pkg.load, onlyasc=1, dump=True) 
            pattern = all(tags in r.findall(payloadStr) for tags in stratumTag)
            # print(payloadStr)            

            if(pattern):
                if(pkg[1].dst not in detected_ips):
                    detected_ips.append(pkg[1].dst)
                    send_alert_to_firewall(pkg[1].dst)
        else:
            continue
    return print("No polls were detected.")

def send_alert_to_firewall(ip):
    print("Blocking address", ip)
    run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])  

def start():
    sniffer = sniff(count=1000, filter="tcp")
    wrpcap("pkt/miner.pcap", sniffer)
    find_stratum("pkt/miner.pcap")
    print("Finished analyzing process.")
    # cpu_spike(duration)
