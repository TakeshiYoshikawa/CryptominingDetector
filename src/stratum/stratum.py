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
                    detected_ips.append(pkg[1].src)

                    send_alert_to_firewall(pkg[1].dst)
                    send_alert_to_firewall(pkg[1].src)
        else:
            continue
    return print("No polls were detected.")

def send_alert_to_firewall(ip):
    print("Blocking address", ip)
    run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])  

def create_pcap(filename, number_of_packets):
    sniffer = sniff(count=number_of_packets, filter="tcp")
    wrpcap("pkt/{0}".format(filename), sniffer)
    return "pkt/{0}".format(filename)

def start():
    filename = "miner.pcap"
    _pcap = create_pcap("miner.pcap", 10)
    find_stratum(_pcap)

    #print("Finished analyzing process.")
    # cpu_spike(duration)