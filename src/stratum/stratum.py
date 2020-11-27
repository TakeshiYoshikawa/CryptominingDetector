import re
from scapy.all import *
from subprocess import run
from numpy import mean
from psutil import cpu_percent, virtual_memory
from collections import *
from time import sleep, time


def time_out(seconds):
    return time() + seconds

def cpu_spike(duration):
    time_limit = time_out(duration)
    while(time() < time_limit):
        cpu_usage = mean(cpu_percent(percpu=True))

        if(cpu_usage > 30.00 and virtual_memory().percent > 70.00): #30% is an alarming average value
            print("CPU and Memory spikes detected")
        sleep(3)

def find_stratum(filename):
    pkgList = rdpcap(filename)
    stratum_flags = []
    stratumTag = ['jsonrpc']
    r = re.compile(r'\bjsonrpc\b | \bmethod\b | \bnonce\b', flags=re.I | re.X)

    for pkg in pkgList:
        if(pkg[1].haslayer(Raw)): 
            payloadStr = linehexdump(pkg.load, onlyasc=1, dump=True) #Convert bytes payload to str
            result2 = all(tags in r.findall(payloadStr) for tags in stratumTag)
            
            # print(payloadStr)
            if(result2):
                return pkg[1].dst
        else:
            continue
    return

#Check firewall rules
def send_firewall_alert(ip):
    run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])  